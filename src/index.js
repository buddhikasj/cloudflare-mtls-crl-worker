import * as asn1js from 'asn1js'
import { Certificate, CertificateRevocationList } from 'pkijs'



// Modern Cloudflare Workers export pattern
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx)
  }
}
   
  // Function to extract CRL Distribution Points from certificate
  function extractCRLDistributionPoints(certDerBase64) {
    try {
      // Decode base64 to binary
      const binaryString = atob(certDerBase64)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }
      
      // Parse the certificate
      const asn1 = asn1js.fromBER(bytes.buffer)
      const certificate = new Certificate({ schema: asn1.result })
      
      // Find the CRL Distribution Points extension (OID: 2.5.29.31)
      const crlDistPointsExt = certificate.extensions?.find(
        ext => ext.extnID === '2.5.29.31'
      )
      
      if (!crlDistPointsExt) {
        console.log('No CRL Distribution Points extension found')
        return null
      }
      
      console.log('CRL extension found, parsing...')
      
      // Parse the extension value
      const crlDistPoints = asn1js.fromBER(crlDistPointsExt.extnValue.valueBlock.valueHex)
      
      // Extract URLs from distribution points - recursive search for URI type (tag 6)
      const urls = []
      
      function extractURIs(obj) {
        if (!obj) return
        
        // Check if this is a URI (context-specific tag 6)
        if (obj.idBlock && obj.idBlock.tagNumber === 6) {
          try {
            const url = String.fromCharCode.apply(null, new Uint8Array(obj.valueBlock.valueHex))
            console.log('Found CRL URL:', url)
            urls.push(url)
          } catch (e) {
            console.error('Error decoding URI:', e)
          }
        }
        
        // Recursively search in nested structures
        if (obj.valueBlock && obj.valueBlock.value) {
          if (Array.isArray(obj.valueBlock.value)) {
            for (const item of obj.valueBlock.value) {
              extractURIs(item)
            }
          } else {
            extractURIs(obj.valueBlock.value)
          }
        }
      }
      
      extractURIs(crlDistPoints.result)
      
      return urls.length > 0 ? urls : null
    } catch (error) {
      console.error('Error extracting CRL Distribution Points:', error)
      console.error('Error stack:', error.stack)
      return null
    }
  }

  function extractCNFromDN(dn) {
    if (!dn || typeof dn !== 'string') return null
    const m = dn.match(/(?:^|,\s*)CN=([^,]+)(?:,|$)/i)
    return m ? m[1] : null
  }


   
  // Function that converts the base64 encoded DER certificate to PEM format
  function toPem(base64) {
    let pem = '-----BEGIN CERTIFICATE-----\n'
    // Add a new line after every 64 characters
    for (let i = 0; i < base64.length; i += 64) {
      pem += base64.slice(i, i + 64) + '\n'
    }
    pem += '-----END CERTIFICATE-----\n'
    // I do not think escape(pem) actually does anything
    return pem
  }

  /**
 * Helper function that converts a buffer to a hex string
 * @param {*} inputBuffer
 */
function bufToHex(inputBuffer) {
  let result = ''
  for (const item of new Uint8Array(inputBuffer, 0, inputBuffer.byteLength)) {
    const str = item.toString(16).toUpperCase()
    if (str.length === 1) result += '0'
    result += str
  }
  return result.trim()
}

/**
 * Fetchs a CRL list, parses out the serial numbers, and stores them into workers kv
 */
async function updateCRL(env, crlUrl, crlKvKey) {
  const crlResp = await fetch(crlUrl)
  if (crlResp.status == 200) {
    const buf = await crlResp.arrayBuffer()
    const asn1 = asn1js.fromBER(buf)
    const crlSimpl = new CertificateRevocationList({
      schema: asn1.result,
    })
    const newCRL = {
      nextUpdate: crlSimpl.nextUpdate.value,
      thisUpdate: crlSimpl.thisUpdate.value,
      revokedSerialNumbers: crlSimpl.revokedCertificates.reduce(
        (revokedSerialNums, cert) => {
          let serialNum = bufToHex(cert.userCertificate.valueBlock.valueHex)
          revokedSerialNums[serialNum] = true
          return revokedSerialNums
        },
        {},
      ),
    }
    await env.CRL_NAMESPACE.put(crlKvKey, JSON.stringify(newCRL))
    return newCRL
  }
  throw new Error(`failed to fetch crl with status ${crlResp.status}`)
}


async function loadCRL(ctx, env, crlUrl, crlKvKey, forceCRLRefresh = false) {
  // Force a refresh of the CRL list if needed
  if (forceCRLRefresh) {
    return await updateCRL(env, crlUrl, crlKvKey)
  }

  // attempt to get the CRL from workers kv first
  let crl = await env.CRL_NAMESPACE.get(crlKvKey, 'json')
  if (!crl) {
    // the CRL wasn't in workers kv, so go fetch it from the source
    crl = await updateCRL(env, crlUrl, crlKvKey)
  }

  // Check to see if we should refresh the CRL
  const nextUpdate = Date.parse(crl.nextUpdate)
  const now = new Date()
  if (now > nextUpdate) {
    // it is time to update the CRL. Out of band send a request to update the workers kv key
    ctx.waitUntil(updateCRL(env, crlUrl, crlKvKey))
  }

  return crl
}


// Helper to build the CN whitelist KV key for a given host header (may include port)
function cnWhitelistKeyForHost(hostHeader) {
  return `CN_WL_${btoa(hostHeader)}`
}

// Loads the CN whitelist map for the given host from KV. Returns an object map or null.
async function loadCNWhitelist(env, hostHeader) {
  const kvKey = cnWhitelistKeyForHost(hostHeader)
  const entry = await env.CN_WHITELIST.get(kvKey, 'json')
  if (!entry || !entry.common_names || typeof entry.common_names !== 'object') {
    return null
  }
  return entry.common_names
}


// Checks the request host against env.MTLS_HOST and optionally passes through.
// Returns an object { host, response } where response is a Response or null.
async function hostGateOrPassThrough(request, env, headers) {
  // Check if the host header matches the target
  let host = headers.get('host')

  console.log('host', host)
  console.log('MTLS_HOST', env.MTLS_HOST)
  if (host !== env.MTLS_HOST) {
    // Pass through without modification for other hosts
    return { host, response: await fetch(request) }
  }
  return { host, response: null }
}


  // Function that handle the request
  async function handleRequest(request, env, ctx) {

    if (
      request.cf &&
      request.cf.tlsClientAuth &&
      request.cf.tlsClientAuth.certPresented &&
      request.cf.tlsClientAuth.certVerified === 'SUCCESS'
    ) {
    
    // Create a headers object from the request headers
    let headers = new Headers(request.headers)
    
    const { host, response } = await hostGateOrPassThrough(request, env, headers)
    if (response) return response  
    
    // KV namespace storing CN whitelist for each host
    const WL_KEY = `CN_WL_${btoa(host)}`;

    // Extract the client certificate common name and set it as a header
    const subjectDN = request.cf.tlsClientAuth.certSubjectDN
    const clientCN = extractCNFromDN(subjectDN)

    // Set the client CN as a header
    if (clientCN) {
      headers.set('X-Client-CN', clientCN)
    }

    
    // Get the client CN allowlist from workers kv
    const clientCNAllowlistMap = await loadCNWhitelist(env, host);
    

    // Fail closed if no allowlist configured for this host
    if (!clientCNAllowlistMap || typeof clientCNAllowlistMap !== 'object') {
      return new Response('client CN allowlist not configured', { status: 403 });
    }

    // Fail closed if the client CN is not in the allowlist
    if (!clientCN || clientCNAllowlistMap[clientCN] !== true) {
      return new Response('client certificate not allowed', { status: 403 });
    }
    

    // Optional header that will force the worker to get an updated CRL list
    const FORCE_CRL_REFRESH_HEADER = 'force-crl-refresh'
    // Check to see if we were asked to force a CRL refresh
    const forceCRLRefresh = request.headers.get(FORCE_CRL_REFRESH_HEADER)
      ? true
      : false


    // Get the base64 encoded DER certificate and subject
    let cert = headers.get('cf-client-cert-der-base64')

    // // Convert the base64 encoded DER certificate to PEM format
    // let pem = toPem(cert)
    // headers.set('X-Forwarded-Client-Cert', btoa(pem))


    // Extract CRL Distribution Points
    let crlDistPoints = extractCRLDistributionPoints(cert)
    
    // console.log('X-Client-Cert-CRL-URLs:', crlDistPoints)

    // Add CRL Distribution Points header if found
    if (crlDistPoints && Array.isArray(crlDistPoints) && crlDistPoints.length > 0) {
      headers.set('X-Client-Cert-CRL-URLs', crlDistPoints.join(','))
      console.log('CRL URLs added to header:', crlDistPoints.join(','))
    } else {
      console.log('No CRL Distribution Points found in certificate')
    }
    
    // Iterate over all CRL distribution points and evaluate revocation
    let loadedAnyCRL = false
    for (const dp of crlDistPoints) {
      const CRL_KV_KEY = `CRL_${btoa(dp)}`
      const CRL_URL = dp
      try {
        const crl = await loadCRL(ctx, env, CRL_URL, CRL_KV_KEY, false)
        if (crl) {
          loadedAnyCRL = true
          // Check if the certificate the user presented is in this CRL
          if (crl.revokedSerialNumbers && crl.revokedSerialNumbers[request.cf.tlsClientAuth.certSerial]) {
            return new Response('Certificate has been revoked', { status: 403 })
          }
        }
      } catch (e) {
        console.error('Failed to load CRL from distribution point:', CRL_URL, e)
        // Continue to next distribution point
      }
    }

    // If none of the CRLs could be loaded, fail closed
    if (!loadedAnyCRL) {
      return new Response('failed to load CRL from any distribution point', { status: 500 })
    }

    // Clone the request with the updated headers
    let requestClone = new Request(request, { headers: headers })
    // Fetch the request
    return fetch(requestClone)
    }

    else {
      return new Response('Certificate Verifications failed ', { status: 403 })
    }

  }