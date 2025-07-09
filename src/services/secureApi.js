import { SecureKeyManager, SecureTransactionHandler } from '../utils/SecureKeyManager';

const BASEURL = 'http://localhost:8000'; // Middleware URL

/**
 * A centralized and secure fetch function to communicate with the middleware.
 * It handles all the cryptographic operations for requests and responses.
 *
 * @param {string} target - The target route key (e.g., 'register', 'login').
 * @param {object} payload - The JSON payload to send to the target service.
 * @param {object} url_params - Optional parameters to be embedded in the URL.
 * @returns {Promise<object>} - The decrypted JSON response from the server.
 */
export async function secureApi(target, payload = {}, url_params = {}) {
  console.log(`[SecureAPI] Initiating request for target: ${target}`);

  // 1. Generate client's signing keypair (for this example, we generate a new one each time)
  // In a real app, this would be retrieved from SecureKeyManager after PIN entry.
  const client_ecdsa_keypair = await SecureKeyManager.generateKeyPair();
  const client_public_key_pem = await SecureKeyManager.exportPublicKeyAsPem(client_ecdsa_keypair.publicKey);
  const client_signature = await SecureTransactionHandler.signTransaction(payload, client_ecdsa_keypair.privateKey);

  // 2. Fetch server's public key for ECDH
  const server_key_response = await fetch(`${BASEURL}/api/middleware/public-key`);
  if (!server_key_response.ok) {
    throw new Error('Failed to fetch server public key.');
  }
  const { public_key: server_public_key_pem } = await server_key_response.json();
  const server_public_key = await SecureTransactionHandler.importServerPublicKey(server_public_key_pem);

  // 3. Perform ECDH to establish a session key
  const ephemeral_ecdh_keypair = await SecureTransactionHandler.generateEphemeralKeyPair();
  const ephemeral_public_key_spki = await window.crypto.subtle.exportKey('spki', ephemeral_ecdh_keypair.publicKey);
  const shared_secret = await SecureTransactionHandler.deriveSharedSecret(ephemeral_ecdh_keypair.privateKey, server_public_key);
  const session_key = await SecureTransactionHandler.deriveSessionKey(shared_secret);

  // 4. Construct the full, secure payload
  const secure_payload = {
    target,
    url_params,
    transaction: payload,
    signature: client_signature,
    public_key: client_public_key_pem,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
  };

  // 5. Encrypt the payload
  const { ciphertext, iv } = await SecureTransactionHandler.encryptPayload(secure_payload, session_key);

  // 6. Send to the middleware gateway
  const gateway_response = await fetch(`${BASEURL}/api/secure/gateway`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ephemeral_pubkey: btoa(String.fromCharCode(...new Uint8Array(ephemeral_public_key_spki))),
      ciphertext,
      iv,
    }),
  });

  if (!gateway_response.ok) {
    // Attempt to decrypt error response if possible
    try {
        const errorData = await gateway_response.json();
        const decryptedError = await SecureTransactionHandler.decryptResponse(errorData, session_key);
        throw new Error(`[${gateway_response.status}] ${decryptedError.error || 'An unknown error occurred.'}`);
    } catch (e) {
        throw new Error(`[${gateway_response.status}] ${e.message || 'Failed to process server error response.'}`);
    }
  }

  // 7. Decrypt the successful response
  const responseData = await gateway_response.json();
  const decryptedResponse = await SecureTransactionHandler.decryptResponse(responseData, session_key);

  console.log(`[SecureAPI] Successfully received and decrypted response for ${target}:`, decryptedResponse);
  return decryptedResponse;
}
