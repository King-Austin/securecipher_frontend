import { SecureKeyManager, SecureTransactionHandler } from '../utils/SecureKeyManager';

const BASEURL = 'http://localhost:8000'; // Middleware URL

// Store the server public key in memory to avoid fetching it for every request
let serverPublicKey = null;
let serverPublicKeyPem = null;

async function getServerPublicKey() {
  if (!serverPublicKey) {
    const response = await fetch(`${BASEURL}/api/middleware/public-key`);
    if (!response.ok) {
      throw new Error('Failed to fetch server public key.');
    }
    const data = await response.json();
    serverPublicKeyPem = data.public_key;
    serverPublicKey = await SecureTransactionHandler.importServerPublicKey(serverPublicKeyPem);
  }
  return { serverPublicKey, serverPublicKeyPem };
}


/**
 * A centralized and secure fetch function to communicate with the middleware.
 * It handles all the cryptographic operations for requests and responses.
 *
 * @param {string} path - The API path (e.g., '/auth/register/').
 * @param {object} payload - The JSON payload to send.
 * @param {object} options - Configuration options { target, keyPair, url_params }.
 * @returns {Promise<object>} - The decrypted JSON response from the server.
 */
async function makeSecureRequest(path, payload = {}, options = {}) {
  const { target, keyPair, url_params = {} } = options;
  console.log(`[SecureAPI] Request for target: ${target}, path: ${path}`);

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

  // 4. Get JWT access token
  const accessToken = localStorage.getItem('accessToken');

  // 5. Construct the secure payload for the middleware
  const secure_payload = {
    target,
    url_params,
    transaction_data: payload,
    client_signature,
    client_public_key: client_public_key_pem,
    auth_token: accessToken, // Include the JWT
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
  };

  // 6. Encrypt the payload
  const { ciphertext, iv } = await SecureTransactionHandler.encryptPayload(secure_payload, session_key);

  // 7. Send to the middleware gateway
  const gateway_response = await fetch(`${BASEURL}/api/secure/gateway`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ephemeral_pubkey: btoa(String.fromCharCode(...new Uint8Array(ephemeral_public_key_spki))),
      ciphertext,
      iv,
    }),
  });

  // 8. Handle response
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

  // If the response contains new tokens (e.g. from a refresh), update them.
  if (decryptedResponse.access) {
    localStorage.setItem('accessToken', decryptedResponse.access);
    console.log('[SecureAPI] New access token stored.');
  }

  return decryptedResponse;
}

/**
 * Attempts to refresh the JWT access token using the stored refresh token.
 * @returns {Promise<boolean>} - True if refresh was successful, false otherwise.
 */
async function refreshToken() {
  console.log('[RefreshToken] Attempting to refresh token...');
  const refreshToken = localStorage.getItem('refreshToken');
  if (!refreshToken) {
    console.log('[RefreshToken] No refresh token found.');
    return false;
  }

  try {
    // We need a keypair to make a secure request, but the payload itself isn't signed by the user
    // as this is an automated process. We'll use a temporary, in-memory key for the ECDH handshake.
    // The server will rely on the validity of the refresh token, not a user signature.
    const tempKeyPair = await SecureKeyManager.generateSigningKeyPair();

    const response = await makeSecureRequest(
      '/auth/token/refresh/', 
      { refresh: refreshToken },
      { target: 'auth_token_refresh', keyPair: tempKeyPair }
    );

    if (response.access) {
      localStorage.setItem('accessToken', response.access);
      // Some refresh strategies also return a new refresh token.
      if (response.refresh) {
        localStorage.setItem('refreshToken', response.refresh);
      }
      console.log('[RefreshToken] Token refresh successful.');
      return true;
    }
    return false;
  } catch (error) {
    console.error('[RefreshToken] Failed to refresh token:', error);
    // If refresh fails, the refresh token is likely invalid, so log out.
    logout();
    return false;
  }
}

// A simple flag to prevent infinite retry loops for token refreshing.
let isRefreshing = false;

/**
 * A wrapper around makeSecureRequest that handles automatic token refreshing.
 * @param {string} path - The API path.
 * @param {object} payload - The JSON payload.
 * @param {object} options - Configuration options.
 * @returns {Promise<object>} - The decrypted JSON response.
 */
async function secureRequestWithRefresh(path, payload, options) {
    try {
        return await makeSecureRequest(path, payload, options);
    } catch (error) {
        // Check if the error is a 401 Unauthorized (or similar) and we haven't already tried refreshing.
        if (error.message.includes('[401') && !isRefreshing) {
            isRefreshing = true;
            const refreshed = await refreshToken();
            isRefreshing = false;

            if (refreshed) {
                console.log('[SecureAPI] Token refreshed, retrying original request...');
                // Retry the original request with the new token.
                return await makeSecureRequest(path, payload, options);
            }
        }
        // If refresh failed or it's another type of error, re-throw it.
        throw error;
    }
}


/**
 * Logs the user out by clearing all stored credentials.
 */
export function logout() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('userPublicKey');
    localStorage.removeItem('encryptedPrivateKey');
    // Optionally, redirect to login page
    window.location.href = '/login';
}


/**
 * Handles the cryptographic login flow.
 * @param {CryptoKeyPair} client_ecdsa_keypair - The user's signing keypair.
 * @returns {Promise<object>} - The JWT token pair { access, refresh }.
 */
export async function cryptoLogin(client_ecdsa_keypair) {
  console.log('[CryptoLogin] Initiating cryptographic login...');

  // 1. Get server's public key
  const { serverPublicKey } = await getServerPublicKey();

  // 2. Create a challenge
  const challenge = crypto.randomUUID();
  const client_public_key_pem = await SecureKeyManager.exportPublicKeyAsPem(client_ecdsa_keypair.publicKey);
  const signature = await SecureTransactionHandler.signTransaction({ challenge }, client_ecdsa_keypair.privateKey);

  // 3. Establish session key via ECDH
  const ephemeral_ecdh_keypair = await SecureTransactionHandler.generateEphemeralKeyPair();
  const ephemeral_public_key_spki = await window.crypto.subtle.exportKey('spki', ephemeral_ecdh_keypair.publicKey);
  const shared_secret = await SecureTransactionHandler.deriveSharedSecret(ephemeral_ecdh_keypair.privateKey, serverPublicKey);
  const session_key = await SecureTransactionHandler.deriveSessionKey(shared_secret);

  // 4. Construct payload for crypto_login endpoint
  const login_payload = {
    public_key: client_public_key_pem,
    challenge,
    signature,
  };

  // 5. Encrypt the payload
  const { ciphertext, iv } = await SecureTransactionHandler.encryptPayload(login_payload, session_key);

  // 6. Send to the middleware's crypto_login endpoint
  const response = await fetch(`${BASEURL}/api/crypto_login/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ephemeral_pubkey: btoa(String.fromCharCode(...new Uint8Array(ephemeral_public_key_spki))),
      ciphertext,
      iv,
    }),
  });

  const responseData = await response.json();
  if (!response.ok) {
    try {
      const decryptedError = await SecureTransactionHandler.decryptResponse(responseData, session_key);
      throw new Error(`Login failed: ${decryptedError.error}`);
    } catch (e) {
      throw new Error(`Login failed: ${e.message}`);
    }
  }

  // 7. Decrypt the successful response (containing tokens)
  const decryptedResponse = await SecureTransactionHandler.decryptResponse(responseData, session_key);
  
  // 8. Store tokens
  if (decryptedResponse.access && decryptedResponse.refresh) {
    localStorage.setItem('accessToken', decryptedResponse.access);
    localStorage.setItem('refreshToken', decryptedResponse.refresh);
  } else {
    throw new Error("Login response did not contain expected tokens.");
  }

  console.log('[CryptoLogin] Login successful, tokens stored.');
  return decryptedResponse;
}

export const secureApi = {
  post: (path, data, options) => secureRequestWithRefresh(path, data, options),
  get: (path, options) => secureRequestWithRefresh(path, undefined, options),
  put: (path, data, options) => secureRequestWithRefresh(path, data, options),
  delete: (path, options) => secureRequestWithRefresh(path, undefined, options),
  cryptoLogin,
  logout,
};

export default secureApi;
