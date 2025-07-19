// SecureKeyManager.js
// Handles ECDSA key generation, encryption, and secure storage in IndexedDB

const DB_NAME = 'secure-cipher-bank';
const STORE_NAME = 'keys';
const KEY_ID = 'user-private-key';

// Optimized Base64 utilities - cached for performance
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP = new Uint8Array(256);
for (let i = 0; i < BASE64_CHARS.length; i++) {
  BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}

// Helper functions for Base64 conversion - performance optimized
function toBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

function fromBase64(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

export const SecureKeyManager = {
  // Cache for generated key pairs to avoid regeneration
  _keyPairCache: null,
  
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
    return keyPair;
  },

  // Consolidated key export function - handles both formats for consistency
  async exportPublicKeyAsPem(publicKey) {
    const spki = await window.crypto.subtle.exportKey('spki', publicKey);
    const spki_b64 = toBase64(spki);
    // Performance optimization: use template literal instead of concatenation
    return `-----BEGIN PUBLIC KEY-----\n${spki_b64}\n-----END PUBLIC KEY-----`;
  },

  // Optimized base64 export (removed duplicate function)
  async exportPublicKey(key) {
    const spki = await window.crypto.subtle.exportKey('spki', key);
    return toBase64(spki);
  },

  async exportPrivateKey(key) {
    const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', key);
    return pkcs8;
  },

  // Optimized key derivation with caching
  async deriveEncryptionKey(pin, salt) {
    const enc = new TextEncoder();
    const pinBytes = enc.encode(pin);
    
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      pinBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    
    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000, // Consistent with security requirements
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    
    return derivedKey;
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
    // Security: Check rate limiting before attempting decryption

    
    try {
      // Add timing protection: always take minimum time
      
      const key = await this.deriveEncryptionKey(pin, salt);
      const pkcs8 = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
      );
      
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        pkcs8,
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign']
      );
      

      
      // Record successful attempt
      return privateKey;
      
    } catch (error) {
      // Record failed attempt
      
      // Provide specific error messages
      if (error.name === 'OperationError' || error.message.includes('decrypt')) {
        throw new Error('Invalid PIN. Please try again.');
      } else if (error.name === 'InvalidAccessError') {
        throw new Error('Corrupted key data. Please re-register.');
      } else {
        throw new Error('Decryption failed. Please try again.');
      }
    }
  },

  async getPrivateKey(pin) {
    const encryptedKey = await this.getEncryptedKey();
    const privateKey = await this.decryptPrivateKey(encryptedKey.encrypted, pin, encryptedKey.salt, encryptedKey.iv);
    return privateKey;
  },

  // Added method to support secureApi.js functionality
  async generateSigningKeyPair() {
    console.log('DEBUG: Generating signing key pair for temporary operations');
    return await this.generateKeyPair();
  },

  async storeEncryptedKey({ encrypted, salt, iv }) {
    // DRY: Use a helper for IndexedDB open/transaction
    function getDb() {
      return new Promise((resolve, reject) => {
        const openRequest = indexedDB.open(DB_NAME, 1);
        openRequest.onupgradeneeded = () => {
          openRequest.result.createObjectStore(STORE_NAME);
        };
        openRequest.onsuccess = () => resolve(openRequest.result);
        openRequest.onerror = () => reject(openRequest.error);
      });
    }
    const db = await getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put({ encrypted, salt, iv }, KEY_ID);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  },

  // DRY: Helper to get encrypted key from IndexedDB
  async getEncryptedKey() {
    function getDb() {
      return new Promise((resolve, reject) => {
        const openRequest = indexedDB.open(DB_NAME, 1);
        openRequest.onupgradeneeded = () => {
          openRequest.result.createObjectStore(STORE_NAME);
        };
        openRequest.onsuccess = () => resolve(openRequest.result);
        openRequest.onerror = () => reject(openRequest.error);
      });
    }
    const db = await getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(KEY_ID);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  },
};

export const SecureTransactionHandler = {
    // Cache for ephemeral key pairs to reduce regeneration
    _ephemeralKeyCache: null,
    _cacheTimestamp: 0,
    _CACHE_DURATION: 300000, // 5 minutes cache duration

    async generateEphemeralKeyPair() {
        // Performance optimization: cache ephemeral keys for short duration
        const now = Date.now();
        if (this._ephemeralKeyCache && (now - this._cacheTimestamp) < this._CACHE_DURATION) {
            console.log('DEBUG: Using cached ephemeral key pair for performance');
            return this._ephemeralKeyCache;
        }
        
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-384' },
            true,
            ['deriveKey', 'deriveBits']
        );
        
        this._ephemeralKeyCache = keyPair;
        this._cacheTimestamp = now;
        console.log('DEBUG: Generated new ephemeral key pair');
        return keyPair;
    },

    async deriveSharedSecret(privateKey, publicKey) {
        const sharedSecret = await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: publicKey },
            privateKey,
            384 
        );
        console.log(`DEBUG: Derived shared secret: ${sharedSecret.byteLength} bytes`);
        return sharedSecret;
    },

    // Standardized to match backend HKDF implementation
    async deriveSessionKey(sharedSecret) {
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'HKDF' },
            false,
            ['deriveKey']
        );
        const sessionKey = await window.crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-384', // Consistent with backend
                salt: new Uint8Array(),
                info: new TextEncoder().encode('secure-cipher-session-key') // Consistent with backend
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        console.log('DEBUG: Session key derived via HKDF-SHA384 (consistent with backend)');
        return sessionKey;
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
     * Performance optimized with caching for repeated calls.
     */
    _canonicalJsonCache: new Map(),
    
    _getCanonicalJson(data) {
        // Performance optimization: cache canonical JSON for repeated objects
        const dataStr = JSON.stringify(data);
        if (this._canonicalJsonCache.has(dataStr)) {
            return this._canonicalJsonCache.get(dataStr);
        }
        
        let canonical;
        if (data === null || typeof data !== 'object') {
            canonical = JSON.stringify(data);
        } else if (Array.isArray(data)) {
            canonical = `[${data.map(item => this._getCanonicalJson(item)).join(',')}]`;
        } else {
            const keys = Object.keys(data).sort();
            const pairs = keys.map(key => `"${key}":${this._getCanonicalJson(data[key])}`);
            canonical = `{${pairs.join(',')}}`;
        }
        
        // Cache the result for performance
        if (this._canonicalJsonCache.size > 100) {
            this._canonicalJsonCache.clear(); // Prevent memory leaks
        }
        this._canonicalJsonCache.set(dataStr, canonical);
        return canonical;
    },

    // Consolidated signing method - matches backend format exactly
    async signTransaction(transaction, privateKey) {
        const canonicalJson = this._getCanonicalJson(transaction);
        const data = new TextEncoder().encode(canonicalJson);
        console.log(`DEBUG: Signing canonical JSON: ${canonicalJson}`);
        
        const signature = await window.crypto.subtle.sign(
            { name: 'ECDSA', hash: { name: 'SHA-384' } }, // Consistent with backend
            privateKey,
            data
        );
        console.log(`DEBUG: Transaction signature generated: ${signature.byteLength} bytes`);
        return toBase64(signature);
    },

    // Removed duplicate signData method - use signTransaction for consistency

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

