import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Check, AlertCircle, Loader } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import {secureApi} from '../services/secureApi';

export default function PINSetup() {
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const navigate = useNavigate();
  const { markPinAsSet } = useAuth();

  const handlePinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 4) {
      setPin(value);
      setError('');
    }
  };

  const handleConfirmPinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 4) {
      setConfirmPin(value);
      setError('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (pin.length !== 4) {
      setError('PIN must be 4 digits');
      return;
    }
    
    if (pin !== confirmPin) {
      setError('PINs do not match');
      return;
    }
    
    setIsLoading(true);
    setError('');
    
    try {
      const response = await secureApi.post(
        '/auth/set_pin/', // This is the target, not the full URL
        { pin },
        { target: 'set_pin' } // The target key for the middleware
      );

      if (response.message === 'Transaction PIN set successfully.') {
        markPinAsSet();
        setIsSuccess(true);
        
        // Navigate to dashboard after 2 seconds
        setTimeout(() => {
          navigate('/dashboard');
        }, 2000);
      } else {
        throw new Error(response.error || 'Failed to set PIN.');
      }
      
    } catch (err) {
      console.error('Error setting PIN:', err);
      const errorMessage = err.response?.data?.error || err.message || 'An error occurred during setup. Please try again.';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-gray-50">
      <div className="flex-1 flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="mx-auto w-full max-w-md">
          <div className="text-center">
            <h2 className="text-3xl font-extrabold text-gray-900">
              Secure Your Account
            </h2>
            <p className="mt-2 text-sm text-gray-600">
              Set up your 4-digit transaction PIN. This will be used to authorize all sensitive actions.
            </p>
          </div>

          <div className="mt-8">
            <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
              {isSuccess ? (
                <div className="text-center">
                  <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                    <Check className="h-6 w-6 text-green-600" />
                  </div>
                  <h3 className="mt-4 text-lg font-medium text-gray-900">PIN Set Successfully!</h3>
                  <p className="mt-2 text-sm text-gray-600">
                    Redirecting you to the dashboard...
                  </p>
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div>
                    <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                      New PIN
                    </label>
                    <div className="mt-1">
                      <input
                        id="pin"
                        name="pin"
                        type="password"
                        maxLength="4"
                        value={pin}
                        onChange={handlePinChange}
                        required
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        placeholder="••••"
                      />
                    </div>
                  </div>

                  <div>
                    <label htmlFor="confirm-pin" className="block text-sm font-medium text-gray-700">
                      Confirm PIN
                    </label>
                    <div className="mt-1">
                      <input
                        id="confirm-pin"
                        name="confirm-pin"
                        type="password"
                        maxLength="4"
                        value={confirmPin}
                        onChange={handleConfirmPinChange}
                        required
                        className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                        placeholder="••••"
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="flex items-center space-x-2 text-sm text-red-600">
                      <AlertCircle className="h-5 w-5" />
                      <span>{error}</span>
                    </div>
                  )}

                  <div>
                    <button
                      type="submit"
                      disabled={isLoading || pin.length !== 4 || pin !== confirmPin}
                      className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isLoading ? (
                        <>
                          <Loader className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" />
                          Setting PIN...
                        </>
                      ) : (
                        'Set Transaction PIN'
                      )}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
      <div className="hidden lg:block relative w-0 flex-1 bg-indigo-700">
        <div className="absolute inset-0 h-full w-full flex flex-col justify-center items-center text-white p-12">
            <Shield size={64} className="mb-4 text-indigo-300"/>
            <h2 className="text-3xl font-bold text-center">Your Security is Our Priority</h2>
            <p className="mt-4 text-lg text-indigo-200 text-center">
              Your transaction PIN adds a crucial layer of security, ensuring that only you can authorize payments and sensitive changes to your account.
            </p>
        </div>
      </div>
    </div>
  );
}
