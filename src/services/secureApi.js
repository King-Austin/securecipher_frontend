import * as SecureKeyManager from '../utils/SecureKeyManager';


// Unified secure request handler for all middleware requests
export async function secureRequest({ target, payload, pin }) {
    console.log('secureRequest payload:', payload); // Debug: should show full registration data

    let identityKeyPair;
    let publicKeyPem;
    try {
        const { encrypted, salt, iv } = await SecureKeyManager.fetchEncryptedPrivateKey();
        identityKeyPair = await SecureKeyManager.decryptPrivateKey(encrypted, pin, salt, iv);
        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        console.log('Identity keypair decrypted successfully');
        console.log('Public key PEM:', publicKeyPem);
    } catch (err) {
        identityKeyPair = await SecureKeyManager.generateSigningKeyPair();
        publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(identityKeyPair.publicKey);
        const { encrypted, salt, iv } = await SecureKeyManager.encryptPrivateKey(identityKeyPair.privateKey, pin);
        await SecureKeyManager.saveEncryptedPrivateKey(encrypted, salt, iv);
        console.log('New identity keypair generated and saved.');
        console.log('Public key PEM:', publicKeyPem);
    }

    // Fetch server public key
    const serverPublicKey = await SecureKeyManager.getServerPublicKey();
    console.log('Server public key imported:', serverPublicKey);

    // Generate ephemeral key pair for session
    const ephemeralKeyPair = await SecureKeyManager.generateEphemeralKeyPair();
    const ephemeralPubkey = SecureKeyManager.toBase64(
        await window.crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey)
    );
    console.log('Ephemeral public key (base64):', ephemeralPubkey);

    // Derive shared secret and session key
    const sharedSecret = await SecureKeyManager.deriveSharedSecret(
        ephemeralKeyPair.privateKey,
        serverPublicKey
    );
    const sessionKey = await SecureKeyManager.deriveSessionKey(sharedSecret);
    console.log('Session key derived:', sessionKey);

    // Prepare payload to sign
    const timestamp = Math.floor(Date.now() / 1000); // Current UNIX timestamp
    const nonce = crypto.randomUUID(); // Modern browsers

    // FIX: Include timestamp and nonce in the signed payload
    const signPayloadDict = {
        transaction_data: payload,
    };
    console.log('Payload to sign:', signPayloadDict); // Debug: should show full registration data, timestamp, nonce

    const canonicalJson = SecureKeyManager.canonicalizeJson(signPayloadDict);
    console.log('Canonical JSON to sign:', canonicalJson);

    const clientSignature = await SecureKeyManager.signTransaction(signPayloadDict, identityKeyPair.privateKey);
    console.log('Client signature (base64):', clientSignature);

    // Build secure payload
    const securePayload = {
        target,
        transaction_data: payload,
        client_signature: clientSignature,
        client_public_key: publicKeyPem,
        nonce,
    };
    console.log('Secure payload (before encryption):', securePayload);

    // Encrypt payload
    const { ciphertext, iv } = await SecureKeyManager.encryptPayload(securePayload, sessionKey);
    console.log('Encrypted payload:', { ciphertext, iv });

    // Send to backend
    const SECURECIPHER_MIDDLEWARE_GATEWAY_URL = 'http://localhost:8000/api/secure/gateway/';
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL) {
        throw new Error('SECURECIPHER_MIDDLEWARE_GATEWAY_URL is not defined in environment variables');
    }
    if (!SECURECIPHER_MIDDLEWARE_GATEWAY_URL.startsWith('http')) {
        throw new Error('SECURECIPHER_MIDDLEWARE_GATEWAY_URL must start with http:// or https://');
    }
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
    console.log("Response data from backend:", responseData);
    if (!res.ok) {
        let errorMsg = 'An unknown error occurred.';
        try {
            const decryptedError = await SecureKeyManager.decryptResponse(responseData, sessionKey);
            errorMsg = decryptedError.error || errorMsg;
        } catch (e) {
            errorMsg = e.message || errorMsg;
        }
        console.error('Error response from backend:', errorMsg);
        throw new Error(`[${res.status}] ${errorMsg}`);
    }
    const decryptedResponse = await SecureKeyManager.decryptResponse(responseData, sessionKey);
    console.log('Decrypted response from backend:', decryptedResponse);
    return decryptedResponse;
}