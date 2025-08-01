// CryptoHelpers.js
// Consolidated crypto helper functions to avoid duplication in components

import { SecureKeyManager, SecureTransactionHandler } from './SecureKeyManager';

// Helper functions for Base64 conversion - consistent with SecureKeyManager
function toBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

function fromBase64(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

/**
 * Consolidated crypto helpers to remove duplication from components
 */
export const CryptoHelpers = {
    // Consolidated function for exporting public keys as PEM
    async exportPublicKeyToPEM(key) {
        return await SecureKeyManager.exportPublicKeyAsPem(key);
    },

    // Consolidated function for signing payloads
    async signPayload(privateKey, data) {
        const dataBytes = new TextEncoder().encode(typeof data === 'string' ? data : JSON.stringify(data));
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-384' }, 
            privateKey, 
            dataBytes
        );
        console.log('DEBUG: Payload signed successfully');
        return toBase64(signature);
    },

    // Consolidated session key derivation - matches backend implementation
    async deriveSessionKey(ephemeralPrivateKey, serverPublicKey) {
        const sharedSecret = await SecureTransactionHandler.deriveSharedSecret(ephemeralPrivateKey, serverPublicKey);
        return await SecureTransactionHandler.deriveSessionKey(sharedSecret);
    },

    // Consolidated payload encryption
    async encryptPayload(sessionKey, data) {
        const initialization_vector = window.crypto.getRandomValues(new Uint8Array(12));
        const payloadBytes = new TextEncoder().encode(typeof data === 'string' ? data : JSON.stringify(data));
        
        const encrypted_data = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: initialization_vector }, 
            sessionKey, 
            payloadBytes
        );
        
        console.log('DEBUG: Payload encrypted successfully');
        return { 
            ciphertext: toBase64(encrypted_data), 
            iv: toBase64(initialization_vector) 
        };
    },

    // Server public key import helper
    async importServerPublicKey(serverPublicKeyPem) {
        return await SecureTransactionHandler.importServerPublicKey(serverPublicKeyPem);
    },

    // Utility for consistent Base64 operations
    toBase64,
    fromBase64
};

export default CryptoHelpers;
