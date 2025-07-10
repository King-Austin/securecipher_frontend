// SecureKeyManager.js
// Handles ECDSA key generation, encryption, and secure storage in IndexedDB

const DB_NAME = 'secure-cipher-bank';
const STORE_NAME = 'keys';
const KEY_ID = 'user-private-key';

// Helper functions for Base64 conversion
function toBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

function fromBase64(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

export const SecureKeyManager = {
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
    return keyPair;
  },

  async exportPublicKeyAsPem(publicKey) {
    const spki = await window.crypto.subtle.exportKey('spki', publicKey);
    const spki_b64 = toBase64(spki);
    return `-----BEGIN PUBLIC KEY-----\n${spki_b64}\n-----END PUBLIC KEY-----`;
  },

  async exportPublicKey(key) {
    const spki = await window.crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(spki)));
  },

  async exportPrivateKey(key) {
    const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', key);
    return pkcs8;
  },

  async deriveEncryptionKey(pin, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(pin),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encryptPrivateKey(privateKey, pin) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveEncryptionKey(pin, salt);
    const pkcs8 = await this.exportPrivateKey(privateKey);
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      pkcs8
    );
    return { encrypted, salt, iv };
  },

  async decryptPrivateKey(encrypted, pin, salt, iv) {
    const key = await this.deriveEncryptionKey(pin, salt);
    const pkcs8 = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );
    return window.crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign']
    );
  },

  async storeEncryptedKey({ encrypted, salt, iv }) {
    return new Promise((resolve, reject) => {
      const open = window.indexedDB.open(DB_NAME, 1);
      open.onupgradeneeded = () => {
        open.result.createObjectStore(STORE_NAME);
      };
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        store.put({ encrypted, salt, iv }, KEY_ID);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
      open.onerror = () => reject(open.error);
    });
  },

  async getEncryptedKey() {
    return new Promise((resolve, reject) => {
      const open = window.indexedDB.open(DB_NAME, 1);
      open.onupgradeneeded = () => {
        open.result.createObjectStore(STORE_NAME);
      };
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const req = store.get(KEY_ID);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      };
      open.onerror = () => reject(open.error);
    });
  },

  async getPrivateKey(pin) {
    const encryptedKey = await this.getEncryptedKey();
    const privateKey = await this.decryptPrivateKey(encryptedKey.encrypted, pin, encryptedKey.salt, encryptedKey.iv);
    return privateKey;
  }
};

export const SecureTransactionHandler = {
    async generateEphemeralKeyPair() {
        return await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-384' },
            true,
            ['deriveKey', 'deriveBits']
        );
    },

    async deriveSharedSecret(privateKey, publicKey) {
        return await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: publicKey },
            privateKey,
            384 
        );
    },

    async deriveSessionKey(sharedSecret) {
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'HKDF' },
            false,
            ['deriveKey']
        );
        return await window.crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-384',
                salt: new Uint8Array(),
                info: new TextEncoder().encode('secure-cipher-session-key')
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    },

    async encryptPayload(payload, sessionKey) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedPayload = new TextEncoder().encode(JSON.stringify(payload));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sessionKey,
            encodedPayload
        );
        return {
            ciphertext: toBase64(ciphertext),
            iv: toBase64(iv)
        };
    },

    async decryptResponse(encryptedResponse, sessionKey) {
        const iv = fromBase64(encryptedResponse.iv);
        const ciphertext = fromBase64(encryptedResponse.ciphertext);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            sessionKey,
            ciphertext
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
    },

    /**
     * Creates a canonical (sorted, no whitespace) JSON string from an object.
     * This is crucial for ensuring signatures match between client and server.
     * @param {object} data - The object to stringify.
     * @returns {string} - The canonical JSON string.
     */
    _getCanonicalJson(data) {
        if (data === null || typeof data !== 'object') {
            return JSON.stringify(data);
        }
        if (Array.isArray(data)) {
            return `[${data.map(this._getCanonicalJson).join(',')}]`;
        }
        const keys = Object.keys(data).sort();
        const pairs = keys.map(key => `"${key}":${this._getCanonicalJson(data[key])}`);
        return `{${pairs.join(',')}}`;
    },

    async signTransaction(transaction, privateKey) {
        // Use the canonical JSON string for signing to ensure consistency.
        const canonicalJson = this._getCanonicalJson(transaction);
        const data = new TextEncoder().encode(canonicalJson);
        const signature = await window.crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-384' } },
            privateKey,
            data
        );
        return toBase64(signature);
    },

    async signData(data, privateKey) {
        const encodedData = new TextEncoder().encode(data);
        const signature = await window.crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-384' } },
            privateKey,
            encodedData
        );
        // Return as hex for easier handling in Django if needed, though b64 is fine
        return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async importServerPublicKey(pem) {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length - 1).trim();
        const binaryDer = fromBase64(pemContents);
        return await window.crypto.subtle.importKey(
            'spki',
            binaryDer,
            { name: 'ECDH', namedCurve: 'P-384' },
            true,
            []
        );
    }
};
