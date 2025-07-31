import { SecureKeyManager, SecureTransactionHandler } from '../utils/SecureKeyManager'; 

const BASEURL = 'https://turbo-space-spoon-69r4q64wgj6c57xp-8000.app.github.dev';
let serverPublicKey = null, keyFetchTimestamp = 0;
const KEY_CACHE_DURATION = 3600000;

async function getServerPublicKey() {
  const now = Date.now();
  if (!serverPublicKey || (now - keyFetchTimestamp) > KEY_CACHE_DURATION) {
    const res = await fetch(`${BASEURL}/api/middleware/public-key`);
    if (!res.ok) throw new Error('Failed to fetch server public key.');
    const { public_key } = await res.json();
    serverPublicKey = await SecureTransactionHandler.importServerPublicKey(public_key);
    keyFetchTimestamp = now;
  }
  return serverPublicKey;
}

async function makeSecureRequest(target, payload = {}) {
  // Always get keypair from SecureKeyManager
  const keyPair = await SecureKeyManager.generateKeyPair();
  console.log('Using key pair:', keyPair);
  if (!keyPair?.privateKey) throw new Error("Unlocked key pair required.");

  const serverPublicKey = await getServerPublicKey();
  const clientPublicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);
  const clientSignature = await SecureTransactionHandler.signTransaction(payload, keyPair.privateKey);

  const ephemeralKeyPair = await SecureTransactionHandler.generateEphemeralKeyPair();
  const ephemeralPubkey = btoa(String.fromCharCode(...new Uint8Array(
    await window.crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey)
  )));
  const sharedSecret = await SecureTransactionHandler.deriveSharedSecret(ephemeralKeyPair.privateKey, serverPublicKey);
  const sessionKey = await SecureTransactionHandler.deriveSessionKey(sharedSecret);

  const securePayload = {
    target,
    transaction_data: payload,
    client_signature: clientSignature,
    client_public_key: clientPublicKeyPem,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
  };
  const { ciphertext, iv } = await SecureTransactionHandler.encryptPayload(securePayload, sessionKey);

  const res = await fetch(`${BASEURL}/api/secure/gateway`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ephemeral_pubkey: ephemeralPubkey, ciphertext, iv }),
  });

  const responseData = await res.json();
  if (!res.ok) {
    let errorMsg = 'An unknown error occurred.';
    try {
      const decryptedError = await SecureTransactionHandler.decryptResponse(responseData, sessionKey);
      errorMsg = decryptedError.error || errorMsg;
    } catch (e) {
      errorMsg = e.message || errorMsg;
    }
    throw new Error(`[${res.status}] ${errorMsg}`);
  }
  return await SecureTransactionHandler.decryptResponse(responseData, sessionKey);
}

function logout() {
  localStorage.removeItem('userPublicKey');
  localStorage.removeItem('pinIsSet');
  serverPublicKey = null; keyFetchTimestamp = 0;
  window.location.href = '/login';
}

export const secureApi = {
  post: makeSecureRequest,
  logout,
};