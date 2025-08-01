import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { KeyRound, Shield, AlertCircle, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { SecureKeyManager } from '../utils/SecureKeyManager';

export default function Login() {
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const { login, setUserData } = useAuth();

  // Redirect to registration if no stored keypair is found
  useEffect(() => {
    (async () => {
      try {
        const encryptedKey = await SecureKeyManager.getEncryptedKey();
        if (!encryptedKey) {
          navigate('/register');
        }
      } catch {
        navigate('/register');
      }
    })();
  }, [navigate]);

  const handleChange = (e) => {
    setPin(e.target.value);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!pin) {
      setError('Please enter your PIN to unlock your key.');
      return;
    }
    
    try {
      setIsLoading(true);
      setError('');
      
      // Authenticate with the PIN
      // TODO: Fetch user data from backend after PIN unlock
      // Example: const { success, userData } = await login(pin);
      const success = await login(pin);
      
      // If you fetch user data here, call setUserData(userData)
      if (success) {
        // setUserData(userData); // Uncomment and use actual userData when available
        // Small delay to show success state before navigation
        setTimeout(() => {
          navigate('/dashboard', { replace: true });
        }, 100);
      } else {
        setError('Invalid PIN. Please try again.');
      }

    } catch (err) {
      console.error('Login error:', err);
      
      // Provide user-friendly error messages
      if (err.message.includes('Invalid PIN')) {
        setError('Invalid PIN. Please check your PIN and try again.');
      } else if (err.message.includes('No encrypted key found')) {
        setError('No account found. Please register first.');
        setTimeout(() => navigate('/register'), 2000);
      } else if (err.message.includes('Account locked')) {
        setError(err.message);
      } else if (err.message.includes('Please wait')) {
        setError('Please wait a moment before trying again.');
      } else {
        setError('Login failed. Please try again or contact support.');
      }
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
              Welcome Back
            </h2>
            <p className="mt-2 text-sm text-gray-600">
              Enter your PIN to securely access your account.
            </p>
          </div>

          <div className="mt-8">
            <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
              <form className="space-y-6" onSubmit={handleSubmit}>
                <div>
                  <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                    Security PIN
                  </label>
                  <div className="mt-1">
                    <input
                      id="pin"
                      name="pin"
                      type="password"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      autoComplete="current-password"
                      autoFocus
                      required
                      value={pin}
                      onChange={handleChange}
                      maxLength="6"
                      className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm transition-colors duration-200"
                      placeholder="Enter your 6-digit PIN"
                      disabled={isLoading}
                    />
                  </div>
                </div>

                {error && (
                  <div className="flex items-center space-x-2 text-sm text-red-600">
                    <AlertCircle className="h-5 w-5" />
                    <p>{error}</p>
                  </div>
                )}

                <div>
                  <button
                    type="submit"
                    disabled={isLoading || !pin}
                    className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors duration-200"
                  >
                    {isLoading ? (
                      <div className="flex items-center">
                        <Loader2 className="animate-spin h-5 w-5 mr-2" />
                        Authenticating...
                      </div>
                    ) : (
                      <div className="flex items-center">
                        <KeyRound className="h-5 w-5 mr-2" />
                        Unlock & Sign In
                      </div>
                    )}
                  </button>
                </div>
              </form>

              <div className="mt-6">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">
                      Or
                    </span>
                  </div>
                </div>

                <div className="mt-6 text-center">
                  <p className="text-sm text-gray-600">
                    Don't have an account?{' '}
                    <Link to="/register" className="font-medium text-green-600 hover:text-green-500">
                      Create one now
                    </Link>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div className="hidden lg:flex lg:flex-1 bg-green-700 items-center justify-center p-10">
        <div className="text-white text-center">
          <Shield size={80} className="mx-auto mb-4" />
          <h1 className="text-3xl font-bold">Passwordless Security</h1>
          <p className="mt-4 text-lg text-green-200">
            Your private key is your password. It's encrypted on your device and unlocked only by you.
          </p>
        </div>
      </div>
    </div>
  );
}
