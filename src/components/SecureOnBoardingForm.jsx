import React, { useState } from 'react';

const BASEURL = 'http://localhost:8000';

// Utility helpers
const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

async function exportPublicKeyToPEM(key) {
  const spki = await window.crypto.subtle.exportKey('spki', key);
  const b64 = toBase64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

async function signPayload(client_private_key, data) {
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, client_private_key, data);
  return toBase64(signature);
}

async function deriveSessionKey(ephemeral_private_key, server_public_key) {
  const shared_secret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: server_public_key },
    ephemeral_private_key,
    384
  );
  
  console.log("🔐 Derived shared secret (first 32 bytes):", Array.from(shared_secret.slice(0, 32)));
  
  // Import the shared secret as an AES-GCM key for session encryption
  return crypto.subtle.importKey('raw', shared_secret.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt']);
}

async function encryptPayload(session_key, data) {
  const initialization_vector = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted_data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: initialization_vector }, session_key, data);
  
  return { 
    ciphertext: toBase64(encrypted_data), 
    iv: toBase64(initialization_vector) 
  };
}

export default function SecureOnboardingForm() {
  const [status, setStatus] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus("Processing secure transaction...");

    try {
      // 1. Prepare user transaction data
      const user_transaction_data = {
        username: "demo_user",
        email: "demo@example.com",
        phone: "1234567890"
      };
      
      // 2. Create deterministic JSON for signing (consistent order)
      const transaction_json_for_signing = JSON.stringify(user_transaction_data, Object.keys(user_transaction_data).sort());
      const transaction_bytes = new TextEncoder().encode(transaction_json_for_signing);
      
      console.log("🔐 Transaction JSON for signing:", transaction_json_for_signing);
      console.log("🔐 Transaction bytes:", Array.from(transaction_bytes));

      // 3. Generate client ECDSA keypair for transaction signing
      const client_ecdsa_keypair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' }, 
        true, 
        ['sign', 'verify']
      );
      
      const client_public_key_pem = await exportPublicKeyToPEM(client_ecdsa_keypair.publicKey);
      const client_signature = await signPayload(client_ecdsa_keypair.privateKey, transaction_bytes);

      console.log("🔐 Client signature created:", client_signature.substring(0, 50) + "...");
      console.log("🔐 Client public key:", client_public_key_pem.substring(0, 100) + "...");

      // 4. Test signature locally (self-verification)
      const local_verification_test = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        client_ecdsa_keypair.publicKey,
        fromBase64(client_signature),
        transaction_bytes
      );
      console.log("🔐 Local signature verification:", local_verification_test);

      // 5. Get server's public key for ECDH key exchange
      setStatus("Fetching server public key...");
      const server_key_response = await fetch(`${BASEURL}/api/middleware/public-key`);
      const { public_key: server_public_key_pem } = await server_key_response.json();
      
      // Parse server public key
      const server_public_key_base64 = server_public_key_pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
      const server_public_key_bytes = fromBase64(server_public_key_base64);
      const server_public_key = await crypto.subtle.importKey('spki', server_public_key_bytes.buffer, { name: 'ECDH', namedCurve: 'P-384' }, true, []);

      // 6. Generate ephemeral ECDH keypair for session key derivation
      setStatus("Generating ephemeral keys...");
      const ephemeral_ecdh_keypair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
      const ephemeral_public_key_spki = await crypto.subtle.exportKey('spki', ephemeral_ecdh_keypair.publicKey);

      // 7. Derive session key using ECDH
      setStatus("Deriving session key...");
      const session_key = await deriveSessionKey(ephemeral_ecdh_keypair.privateKey, server_public_key);
      
      // 8. Create and encrypt payload
      setStatus("Encrypting payload...");
      const secure_payload = { 
        target: "registration", 
        tx: user_transaction_data, 
        sig_p: client_signature,     // Client signature
        q_p: client_public_key_pem   // Client public key
      };
      
      const payload_bytes = new TextEncoder().encode(JSON.stringify(secure_payload));
      const { ciphertext, iv } = await encryptPayload(session_key, payload_bytes);

      // 9. Send encrypted payload to SecureCipher gateway
      setStatus("Sending to SecureCipher gateway...");
      const gateway_response = await fetch(`${BASEURL}/api/secure/gateway`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ephemeral_pubkey: toBase64(ephemeral_public_key_spki),
          ciphertext,
          iv
        })
      });

      const result = await gateway_response.json();
      setStatus(`✅ ${result.status || JSON.stringify(result)}`);
      
    } catch (error) {
      console.error('❌ SecureCipher Error:', error);
      setStatus(`❌ Error: ${error.message}`);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-xl shadow-md mt-10">
      <h2 className="text-xl font-semibold mb-4">🔐 SecureCipher: Secure Transaction</h2>
      <form onSubmit={handleSubmit}>
        <button
          type="submit"
          className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full"
        >
          🔐 Submit Secure Transaction
        </button>
      </form>
      {status && (
        <div className="mt-4 p-4 bg-gray-100 rounded">
          <p className="text-sm font-mono">🔐 Status: {status}</p>
        </div>
      )}
    </div>
  );
}
