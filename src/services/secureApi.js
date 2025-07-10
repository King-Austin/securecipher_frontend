import { SecureKeyManager, SecureTransactionHandler } from '../utils/SecureKeyManager';

const BASEURL = 'http://localhost:8000'; // Middleware URL

/**
 * A centralized and secure fetch function to communicate with the middleware.
 * It handles all the cryptographic operations for requests and responses.
 *
 * @param {string} target - The target route key (e.g., 'register', 'login').
 * @param {object} payload - The JSON payload to send to the target service.
 * @param {object} keyPair - The user's unlocked keypair from AuthContext.
 * @param {object} url_params - Optional parameters to be embedded in the URL.
 * @returns {Promise<object>} - The decrypted JSON response from the server.
 */
export async function secureApi(target, payload = {}, keyPair, url_params = {}) {
  console.log(`[SecureAPI] Initiating request for target: ${target}`);

  if (!keyPair || !keyPair.privateKey) {
    throw new Error("Cannot make secure API call: User's key pair is not available or unlocked.");
  }

  // 1. Sign the transaction payload with the in-memory private key
  const client_public_key_pem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);
  const client_signature = await SecureTransactionHandler.signTransaction(payload, keyPair.privateKey);

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

  // 6. Get the JWT access token from storage
  const accessToken = localStorage.getItem('accessToken');

  // 7. Send to the middleware gateway with Authorization header
  const gateway_response = await fetch(`${BASEURL}/api/secure/gateway`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`
    },
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

  // 8. Decrypt the successful response
  const responseData = await gateway_response.json();
  const decryptedResponse = await SecureTransactionHandler.decryptResponse(responseData, session_key);

  console.log(`[SecureAPI] Successfully received and decrypted response for ${target}:`, decryptedResponse);
  return decryptedResponse;
}

/**
 * Handles the cryptographic login flow.
 * @param {CryptoKeyPair} client_ecdsa_keypair - The user's signing keypair.
 * @returns {Promise<object>} - The JWT token pair { access, refresh }.
 */
export async function cryptoLogin(client_ecdsa_keypair) {
  console.log('[CryptoLogin] Initiating cryptographic login...');

  // 1. Fetch server's public key for ECDH
  const server_key_response = await fetch(`${BASEURL}/api/middleware/public-key`);
  if (!server_key_response.ok) throw new Error('Failed to fetch server public key.');
  const { public_key: server_public_key_pem } = await server_key_response.json();
  const server_public_key = await SecureTransactionHandler.importServerPublicKey(server_public_key_pem);

  // 2. Perform ECDH to establish a session key
  const ephemeral_ecdh_keypair = await SecureTransactionHandler.generateEphemeralKeyPair();
  const ephemeral_public_key_spki = await window.crypto.subtle.exportKey('spki', ephemeral_ecdh_keypair.publicKey);
  const shared_secret = await SecureTransactionHandler.deriveSharedSecret(ephemeral_ecdh_keypair.privateKey, server_public_key);
  const session_key = await SecureTransactionHandler.deriveSessionKey(shared_secret);

  // 3. Create and sign the challenge
  const challenge = `login-attempt-${Date.now()}`;
  const signature = await SecureTransactionHandler.signData(challenge, client_ecdsa_keypair.privateKey);
  const client_public_key_pem = await SecureKeyManager.exportPublicKeyAsPem(client_ecdsa_keypair.publicKey);

  // 4. Construct and encrypt the login payload
  const login_payload = {
    public_key: client_public_key_pem,
    challenge,
    signature,
  };
  const { ciphertext, iv } = await SecureTransactionHandler.encryptPayload(login_payload, session_key);

  // 5. Send to the crypto-login endpoint
  const response = await fetch(`${BASEURL}/api/auth/crypto-login/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ephemeral_pubkey: btoa(String.fromCharCode(...new Uint8Array(ephemeral_public_key_spki))),
      ciphertext,
      iv,
    }),
  });

  if (!response.ok) {
    // If the response is not OK, try to decrypt the error message from the body
    try {
      const errorData = await response.json();
      const decryptedError = await SecureTransactionHandler.decryptResponse(errorData, session_key);
      throw new Error(`[${response.status}] ${decryptedError.error || 'An unknown error occurred during login.'}`);
    } catch (e) {
      // If decryption fails, throw a generic error
      throw new Error(`Login failed with status ${response.status}. Could not decrypt error details.`);
    }
  }

  const responseData = await response.json();

  console.log('[CryptoLogin] Login successful. Tokens received.');
  // In a real app, you would store these tokens securely (e.g., access in memory, refresh in HttpOnly cookie)
  return responseData;
}
