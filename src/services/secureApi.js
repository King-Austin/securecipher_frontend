import { SecureKeyManager, SecureTransactionHandler } from '../utils/SecureKeyManager';

const BASEURL = 'http://localhost:8000'; // Middleware URL

// Store the server public key in memory to avoid fetching it for every request (performance optimization)
let serverPublicKey = null;
let serverPublicKeyPem = null;
let keyFetchTimestamp = 0;
const KEY_CACHE_DURATION = 3600000; // 1 hour cache for server public key

async function getServerPublicKey() {
  const now = Date.now();
  if (!serverPublicKey || (now - keyFetchTimestamp) > KEY_CACHE_DURATION) {
    console.log('DEBUG: Fetching server public key (cache expired or missing)');
    const response = await fetch(`${BASEURL}/api/middleware/public-key`);
    if (!response.ok) {
      throw new Error('Failed to fetch server public key.');
    }
    const data = await response.json();
    serverPublicKeyPem = data.public_key;
    serverPublicKey = await SecureTransactionHandler.importServerPublicKey(serverPublicKeyPem);
    keyFetchTimestamp = now;
    console.log('DEBUG: Server public key cached successfully');
  }
  return { serverPublicKey, serverPublicKeyPem };
}


/**
 * A centralized and secure fetch function to communicate with the middleware.
 * It handles all the cryptographic operations for requests and responses.
 * Updated to work without JWT tokens - uses pure cryptographic authentication.
 *
 * @param {string} target - The target routing key (e.g., 'auth_register').
 * @param {object} payload - The JSON payload to send.
 * @param {object} options - Configuration options { keyPair, url_params }.
 * @returns {Promise<object>} - The decrypted JSON response from the server.
 */
async function makeSecureRequest(target, payload = {}, options = {}) {
  const { keyPair, url_params = {} } = options;
  console.log(`[SecureAPI] Request for target: ${target}`);

  if (!keyPair || !keyPair.privateKey) {
    throw new Error("Secure API call requires an unlocked key pair.");
  }

  // 1. Get server's public key (from memory or fetch)
  const { serverPublicKey, serverPublicKeyPem } = await getServerPublicKey();

  // 2. Sign the payload
  const client_public_key_pem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);
  const client_signature = await SecureTransactionHandler.signTransaction(payload, keyPair.privateKey);

  // 3. Establish session key via ECDH
  const ephemeral_ecdh_keypair = await SecureTransactionHandler.generateEphemeralKeyPair();
  const ephemeral_public_key_spki = await window.crypto.subtle.exportKey('spki', ephemeral_ecdh_keypair.publicKey);
  const shared_secret = await SecureTransactionHandler.deriveSharedSecret(ephemeral_ecdh_keypair.privateKey, serverPublicKey);
  const session_key = await SecureTransactionHandler.deriveSessionKey(shared_secret);

  // 4. Construct the secure payload for the middleware (no JWT/auth tokens needed)
  const secure_payload = {
    target,
    url_params,
    transaction_data: payload,
    client_signature,
    client_public_key: client_public_key_pem,
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

  // 7. Handle response
  const responseData = await gateway_response.json();
  if (!gateway_response.ok) {
    try {
      const decryptedError = await SecureTransactionHandler.decryptResponse(responseData, session_key);
      throw new Error(`[${gateway_response.status}] ${decryptedError.error || 'An unknown error occurred.'}`);
    } catch (e) {
      throw new Error(`[${gateway_response.status}] ${e.message || 'Failed to process server error response.'}`);
    }
  }

  const decryptedResponse = await SecureTransactionHandler.decryptResponse(responseData, session_key);
  console.log(`[SecureAPI] Decrypted response for ${target}:`, decryptedResponse);

  return decryptedResponse;
}

/**
 * A wrapper around makeSecureRequest for consistent API calls.
 * No token refresh needed since we use cryptographic authentication.
 */
async function secureRequestWithAuth(target, payload, options) {
    try {
        return await makeSecureRequest(target, payload, options);
    } catch (error) {
        // Log error and re-throw for handling by calling component
        console.error(`[SecureAPI] Request failed for ${target}:`, error);
        throw error;
    }
}


/**
 * Logs the user out by clearing all stored credentials.
 * Updated for cryptographic authentication (no JWT tokens).
 */
function logout() {
    // Clear any remaining token-related data (for backward compatibility)
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('userPublicKey');
    localStorage.removeItem('pinIsSet');
    
    // Clear server public key cache
    serverPublicKey = null;
    serverPublicKeyPem = null;
    keyFetchTimestamp = 0;
    
    console.log('[Logout] All credentials cleared');
    
    // Optionally, redirect to login page
    window.location.href = '/login';
}


// Updated API interface for cryptographic authentication
export const secureApi = {
  // Main method for making secure requests
  call: (target, payload, options) => secureRequestWithAuth(target, payload, options),
  
  // Convenience methods for different HTTP-like operations
  post: (target, payload, options) => secureRequestWithAuth(target, payload, { ...options, method: 'POST' }),
  get: (target, options) => secureRequestWithAuth(target, undefined, { ...options, method: 'GET' }),
  put: (target, payload, options) => secureRequestWithAuth(target, payload, { ...options, method: 'PUT' }),
  delete: (target, options) => secureRequestWithAuth(target, undefined, { ...options, method: 'DELETE' }),
  
  // Utility functions
  logout
};

// Default export for backward compatibility
export default function secureApiCall(target, payload, options) {
  return secureRequestWithAuth(target, payload, options);
}

export { logout };
