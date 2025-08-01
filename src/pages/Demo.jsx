import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { secureApi } from '../services/secureApi';

export default function Demo() {
  const { unlockedKeyPair, isAuthenticated } = useAuth();
  const [status, setStatus] = useState('');
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);

  const testSecureCall = async (target, testData) => {
    if (!isAuthenticated || !unlockedKeyPair) {
      setStatus('❌ Please login first to use secure API');
      return;
    }

    setLoading(true);
    setStatus(`🔄 Testing ${target}...`);
    setResponse(null);

    try {
      const result = await secureApi.call(target, testData, { keyPair: unlockedKeyPair });
      setResponse(result);
      setStatus(`✅ ${target} successful!`);
    } catch (error) {
      console.error('Secure API Error:', error);
      setStatus(`❌ ${target} failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const demoActions = [
    {
      name: 'Test Registration',
      target: 'auth_register',
      data: {
        username: 'demo_user',
        email: 'demo@example.com',
        phone: '+1234567890',
        first_name: 'Demo',
        last_name: 'User'
      }
    },
    {
      name: 'Get User Profile',
      target: 'user_get_profile',
      data: {}
    },
    {
      name: 'List Accounts',
      target: 'accounts_list',
      data: {}
    },
    {
      name: 'Test Transaction',
      target: 'transactions_transfer',
      data: {
        amount: 100.00,
        recipient_account: '1234567890',
        description: 'Demo transfer'
      }
    }
  ];

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h1 className="text-3xl font-bold text-gray-800 mb-6">
          SecureCipher API Demonstration
        </h1>
        
        <div className="mb-6 p-4 bg-blue-50 rounded-lg">
          <h2 className="text-lg font-semibold text-blue-800 mb-2">System Status</h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Authentication:</span> 
              <span className={`ml-2 ${isAuthenticated ? 'text-green-600' : 'text-red-600'}`}>
                {isAuthenticated ? '✅ Authenticated' : '❌ Not Authenticated'}
              </span>
            </div>
            <div>
              <span className="font-medium">Key Pair:</span> 
              <span className={`ml-2 ${unlockedKeyPair ? 'text-green-600' : 'text-red-600'}`}>
                {unlockedKeyPair ? '✅ Unlocked' : '❌ Locked'}
              </span>
            </div>
          </div>
        </div>

        {!isAuthenticated ? (
          <div className="text-center p-8 bg-yellow-50 rounded-lg">
            <p className="text-lg text-yellow-800 mb-4">
              Please login first to test the secure API
            </p>
            <a 
              href="/login" 
              className="inline-block bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Go to Login
            </a>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              {demoActions.map((action, index) => (
                <button
                  key={index}
                  onClick={() => testSecureCall(action.target, action.data)}
                  disabled={loading}
                  className="p-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <div className="text-left">
                    <div className="font-semibold">{action.name}</div>
                    <div className="text-sm opacity-90">{action.target}</div>
                  </div>
                </button>
              ))}
            </div>

            {status && (
              <div className="mb-4 p-4 bg-gray-100 rounded-lg">
                <p className="font-semibold">Status:</p>
                <p className="text-sm">{status}</p>
              </div>
            )}

            {response && (
              <div className="p-4 bg-green-50 rounded-lg">
                <p className="font-semibold text-green-800 mb-2">Server Response:</p>
                <pre className="bg-gray-800 text-green-400 p-4 rounded text-sm overflow-auto max-h-96">
                  {JSON.stringify(response, null, 2)}
                </pre>
              </div>
            )}
          </>
        )}

        <div className="mt-8 p-4 bg-gray-50 rounded-lg">
          <h3 className="font-semibold text-gray-800 mb-2">How it works:</h3>
          <ul className="text-sm text-gray-600 space-y-1">
            <li>• Each API call uses ECDSA P-384 signature for authentication</li>
            <li>• ECDH key exchange establishes session encryption</li>
            <li>• AES-GCM encrypts all data in transit</li>
            <li>• No JWT tokens - pure graphic authentication</li>
            <li>• Middleware validates signatures and forwards to banking API</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
