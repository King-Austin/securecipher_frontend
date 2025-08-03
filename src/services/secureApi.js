import * as SecureKeyManager from '../utils/SecureKeyManager';


// Unified secure request handler for all middleware requests
export async function secureRequest({ target, payload, pin }) {
    // Try to fetch and decrypt identity keypair from IndexedDB
    let identityKeyPair;
    let publicKeyPem;
    try {
        const { encrypted, salt, iv } = await SecureKeyManager.fetchEncryptedPrivateKey();
        identityKeyPair = await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);
        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
    } catch (err) {
        // If not present, generate new identity keypair and save
        identityKeyPair = await SecureKeyManager.generateSigningKeyPair();
        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        const { encrypted, salt, iv } = await SecureKeyManager.encryptPrivateKey(identityKeyPair.privateKey, pin);
        await SecureKeyManager.saveEncryptedPrivateKey(encrypted, salt, iv);
    }

    // Fetch server public key
    const serverPublicKey = await SecureKeyManager.getServerPublicKey();

    // Generate ephemeral key pair for session
    const ephemeralKeyPair = await SecureKeyManager.generateEphemeralKeyPair();
    const ephemeralPubkey = SecureKeyManager.toBase64(
        await window.crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey)
    );

    // Derive shared secret and session key
    const sharedSecret = await SecureKeyManager.deriveSharedSecret(
        ephemeralKeyPair.privateKey,
        serverPublicKey
    );
    const sessionKey = await SecureKeyManager.deriveSessionKey(sharedSecret);

    // Prepare payload to sign
    const nonce = crypto.randomUUID();
    const timestamp = Math.floor(Date.now() / 1000);
    const signPayloadDict = {
        transaction_data: payload,
        timestamp,
        nonce,
    };
    const clientSignature = await SecureKeyManager.signTransaction(signPayloadDict, identityKeyPair.privateKey);

    // Build secure payload
    const securePayload = {
        target,
        transaction_data: payload,
        client_signature: clientSignature,
        client_public_key: publicKeyPem,
        timestamp,
        nonce,
    };

    // Encrypt payload
    const { ciphertext, iv } = await SecureKeyManager.encryptPayload(securePayload, sessionKey);

    // Send to backend
    const SECURECIPHER_MIDDLEWARE_GATEWAY_URL = import.meta.env.VITE_SECURECIPHER_MIDDLEWARE_GATEWAY_URL;
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL) {
        throw new Error('SECURECIPHER_MIDDLEWARE_GATEWAY_URL is not defined in environment variables');
    }
    // Ensure the URL is valid
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL.startsWith('http')) {
        throw new Error('SECURECIPHER_MIDDLEWARE_GATEWAY_URL must start with http:// or https://');
    }
    // Make the request to the middleware gateway 
    const res = await fetch(SECURECIPHER_MIDDLEWARE_GATEWAY_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
        body: JSON.stringify({
            ephemeral_pubkey: ephemeralPubkey,
            ciphertext,
            iv
        }),
        credentials: 'same-origin'
    });

    // Handle response
    const responseData = await res.json();
    if (!res.ok) {
        let errorMsg = 'An unknown error occurred.';
        try {
            const decryptedError = await SecureKeyManager.decryptResponse(responseData, sessionKey);
            errorMsg = decryptedError.error || errorMsg;
        } catch (e) {
            errorMsg = e.message || errorMsg;
        }
        throw new Error(`[${res.status}] ${errorMsg}`);
    }
    return await SecureKeyManager.decryptResponse(responseData, sessionKey);
}