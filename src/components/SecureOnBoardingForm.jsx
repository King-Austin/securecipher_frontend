import React, { useState } from 'react';
import { secureApi } from '../services/secureApi';
import { useAuth } from '../context/AuthContext';

export default function SecureOnboardingForm() {
  const [status, setStatus] = useState(null);
  const [decryptedResponseObject, setDecryptedResponseObject] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus("Processing secure transaction...");
    setDecryptedResponseObject(null);

    try {
      const user_transaction_data = {
        username: "demo_user",
        email: "demo@example.com",
        phone: "1234567890"
      };

      const response = await secureApi.post('register', user_transaction_data);
      
      setDecryptedResponseObject(response);
      setStatus(`✅ Request to 'register' was successful!`);
      
    } catch (error) {
      console.error('❌ Secure API Error:', error);
      setStatus(`❌ Error: ${error.message}`);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 border rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6">Secure Onboarding</h2>
      <form onSubmit={handleSubmit}>
        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 transition-colors"
        >
          Initiate Secure Transaction
        </button>
      </form>
      {status && (
        <div className="mt-4 p-4 bg-gray-100 rounded-lg">
          <p className="font-semibold">Status:</p>
          <p className="text-sm">{status}</p>
        </div>
      )}
      {decryptedResponseObject && (
        <div className="mt-4 p-4 bg-green-100 rounded-lg">
            <p className="font-semibold">Decrypted Server Response:</p>
            <div className="text-sm text-green-800">
              {Object.entries(decryptedResponseObject).map(([key, value]) => (
                <div key={key} className="mt-2">
                  <strong className="font-medium">{key}:</strong>
                  <pre className="whitespace-pre-wrap bg-gray-200 p-2 rounded mt-1 text-gray-800">
                    {typeof value === 'object' ? JSON.stringify(value, null, 2) : value.toString()}
                  </pre>
                </div>
              ))}
            </div>
        </div>
      )}
    </div>
  );
}
