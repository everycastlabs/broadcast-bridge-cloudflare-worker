// Function to convert PEM format to an ArrayBuffer for Web Crypto API
export function pemToArrayBuffer(pem) {
  const b64Lines = pem.split('\n').filter(line => line.trim().length > 0 && !line.includes('BEGIN') && !line.includes('END'));
  const b64 = b64Lines.join('');
  const binaryString = atob(b64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Function to create a custom token
export async function createCustomToken(serviceAccount, uid, claims) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const payload = {
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: nowSeconds,
    exp: nowSeconds + 3600, // Maximum expiration time is one hour
    uid: uid,
    claims
  };

  // Convert the payload to a string and base64-url encode it
  const header = {
    alg: "RS256",
    typ: "JWT"
  };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  // Import the private key
  const privateKeyArrayBuffer = pemToArrayBuffer(serviceAccount.private_key);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyArrayBuffer,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['sign']
  );

  // Sign the data
  const signatureArrayBuffer = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(dataToSign)
  );

  // Convert the signature to base64-url
  const signature = new Uint8Array(signatureArrayBuffer);
  let base64Signature = btoa(String.fromCharCode(...signature));
  base64Signature = base64Signature.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  // Return the final JWT
  return `${dataToSign}.${base64Signature}`;
}
