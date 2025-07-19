import { useState, useEffect } from 'react';
import { ArrowRight, Building, AlertCircle, Check, Loader, Shield } from 'lucide-react';
import secureApi from '../services/secureApi';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';


export default function SendMoney() {

  const navigate = useNavigate();

  useEffect(() => {
    const hasKeys =
      localStorage.getItem('pinIsSet');
    if (!hasKeys) {
      navigate('/register', { replace: true });
    }
  }, [navigate]);



  const [step, setStep] = useState(1);
  const [transactionData, setTransactionData] = useState({
    to_account: '',
    amount: '',
    description: ''
  });
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [transactionResult, setTransactionResult] = useState(null);
  const [accountDetails, setAccountDetails] = useState(null);
  
  const { isAuthenticated } = useAuth();
  
  useEffect(() => {
    const fetchAccountDetails = async () => {
      if (isAuthenticated) {
        try {
          setLoading(true);
          // Assuming 'list_accounts' returns an array and we use the first one.
          const response = await secureApi.get('/accounts/', { target: 'list_accounts' });
          if (response && response.length > 0) {
            setAccountDetails(response[0]);
          } else {
            setError("Could not fetch account details.");
          }
        } catch (err) {
          console.error('Error fetching account details:', err);
          setError(err.message || 'Failed to load account information.');
        } finally {
          setLoading(false);
        }
      }
    };
    
    fetchAccountDetails();
  }, [isAuthenticated]);
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setTransactionData(prev => ({ ...prev, [name]: value }));
    setError('');
  };
  
  const handlePinChange = (e) => {
    const value = e.target.value.replace(/[^0-9]/g, '');
    if (value.length <= 4) {
      setPin(value);
      setError('');
    }
  };
  
  const handleNextStep = () => {
    if (step === 1) {
      if (!transactionData.to_account || !transactionData.amount) {
        setError('Please fill in all required fields.');
        return;
      }
      if (parseFloat(transactionData.amount) <= 0) {
        setError('Amount must be greater than zero.');
        return;
      }
      if (accountDetails && parseFloat(transactionData.amount) > parseFloat(accountDetails.available_balance)) {
        setError('Insufficient funds.');
        return;
      }
      setStep(2);
    }
  };
  
  const handlePrevStep = () => {
    if (step > 1) {
      setStep(step - 1);
      setError('');
    }
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (pin.length !== 4) {
      setError('Please enter your 4-digit PIN.');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      const payload = {
        from_account: accountDetails.account_number,
        to_account: transactionData.to_account,
        amount: transactionData.amount,
        description: transactionData.description || 'Fund Transfer',
        pin: pin, // The PIN is now part of the payload
      };

      const response = await secureApi.post(
        '/transactions/transfer/', 
        payload,
        { target: 'transfer' }
      );

      if (response.success) {
        setTransactionResult(response);
        setSuccess(true);
      } else {
        throw new Error(response.error || 'Transaction failed. Please try again.');
      }
      
    } catch (err) {
      console.error('Transfer Error:', err);
      const errorMessage = err.response?.data?.error || err.message || 'An unexpected error occurred.';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setStep(1);
    setTransactionData({ to_account: '', amount: '', description: '' });
    setPin('');
    setError('');
    setSuccess(false);
    setTransactionResult(null);
    // Re-fetch account details in case balance changed
    const fetchAccountDetails = async () => {
        try {
          const response = await secureApi.get('/accounts/', { target: 'list_accounts' });
          if (response && response.length > 0) setAccountDetails(response[0]);
        } catch (err) { console.error(err); }
    };
    fetchAccountDetails();
  };

  if (loading && !accountDetails) {
    return (
        <div className="flex justify-center items-center h-64">
            <Loader className="animate-spin h-8 w-8 text-indigo-600" />
            <p className="ml-4 text-gray-600">Loading account details...</p>
        </div>
    );
  }

  if (error && !accountDetails) {
      return (
          <div className="text-center p-8 bg-red-50 rounded-lg">
              <AlertCircle className="mx-auto h-12 w-12 text-red-400" />
              <h3 className="mt-2 text-sm font-medium text-red-800">Failed to load account details</h3>
              <p className="mt-1 text-sm text-red-700">{error}</p>
          </div>
      );
  }

  if (success) {
    return (
      <div className="max-w-lg mx-auto p-8 bg-white shadow-lg rounded-lg text-center">
        <Check className="mx-auto h-16 w-16 text-green-500 bg-green-100 rounded-full p-2" />
        <h2 className="mt-4 text-2xl font-bold text-gray-800">Transfer Successful!</h2>
        <p className="mt-2 text-gray-600">
          You have successfully sent <strong>₦{parseFloat(transactionData.amount).toLocaleString()}</strong> to account <strong>{transactionData.to_account}</strong>.
        </p>
        <div className="mt-6 text-left bg-gray-50 p-4 rounded-md">
            <p className="text-sm text-gray-500">Transaction ID:</p>
            <p className="font-mono text-xs text-gray-800 break-all">{transactionResult?.debit_transaction_id}</p>
        </div>
        <button
          onClick={resetForm}
          className="mt-8 w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          Make Another Transfer
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto bg-white p-8 rounded-xl shadow-lg">
        <div className="flex justify-between items-center mb-6">
            <h1 className="text-2xl font-bold text-gray-800">Send Money</h1>
            {accountDetails && (
                <div className="text-right">
                    <p className="text-sm text-gray-500">Available Balance</p>
                    <p className="text-xl font-semibold text-indigo-600">
                        ₦{parseFloat(accountDetails.available_balance).toLocaleString()}
                    </p>
                </div>
            )}
        </div>

        {/* Stepper */}
        <div className="flex items-center mb-8">
            <div className={`flex-1 text-center ${step >= 1 ? 'text-indigo-600' : 'text-gray-400'}`}>
                <div className="mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center bg-white">1</div>
                <p className="text-xs mt-1">Details</p>
            </div>
            <div className={`flex-1 h-px ${step > 1 ? 'bg-indigo-600' : 'bg-gray-300'}`}></div>
            <div className={`flex-1 text-center ${step >= 2 ? 'text-indigo-600' : 'text-gray-400'}`}>
                <div className="mx-auto h-8 w-8 rounded-full border-2 flex items-center justify-center bg-white">2</div>
                <p className="text-xs mt-1">Confirm</p>
            </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
                <div className="flex items-center space-x-2 text-sm text-red-600 bg-red-50 p-3 rounded-md">
                    <AlertCircle className="h-5 w-5" />
                    <span>{error}</span>
                </div>
            )}

            {step === 1 && (
                <div>
                    <h3 className="text-lg font-medium text-gray-700 mb-4">Recipient Details</h3>
                    <div className="space-y-4">
                        <div>
                            <label htmlFor="to_account" className="block text-sm font-medium text-gray-700">
                                Recipient Account Number
                            </label>
                            <input
                                type="text"
                                name="to_account"
                                id="to_account"
                                value={transactionData.to_account}
                                onChange={handleChange}
                                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                                placeholder="0123456789"
                            />
                        </div>
                        <div>
                            <label htmlFor="amount" className="block text-sm font-medium text-gray-700">
                                Amount (₦)
                            </label>
                            <input
                                type="number"
                                name="amount"
                                id="amount"
                                value={transactionData.amount}
                                onChange={handleChange}
                                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                                placeholder="5000.00"
                            />
                        </div>
                        <div>
                            <label htmlFor="description" className="block text-sm font-medium text-gray-700">
                                Description (Optional)
                            </label>
                            <input
                                type="text"
                                name="description"
                                id="description"
                                value={transactionData.description}
                                onChange={handleChange}
                                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                                placeholder="e.g., For groceries"
                            />
                        </div>
                    </div>
                    <div className="mt-6">
                        <button
                            type="button"
                            onClick={handleNextStep}
                            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                        >
                            Continue
                        </button>
                    </div>
                </div>
            )}

            {step === 2 && (
                <div>
                    <h3 className="text-lg font-medium text-gray-700 mb-4">Confirm Transaction</h3>
                    <div className="bg-gray-50 p-4 rounded-lg space-y-3">
                        <div className="flex justify-between">
                            <span className="text-gray-600">Sending to:</span>
                            <span className="font-medium text-gray-800">{transactionData.to_account}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-gray-600">Amount:</span>
                            <span className="font-bold text-xl text-indigo-600">₦{parseFloat(transactionData.amount).toLocaleString()}</span>
                        </div>
                        {transactionData.description && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Description:</span>
                                <span className="font-medium text-gray-800">{transactionData.description}</span>
                            </div>
                        )}
                    </div>
                    <div className="mt-6">
                        <label htmlFor="pin" className="block text-sm font-medium text-gray-700">
                            Enter your 4-digit PIN to authorize
                        </label>
                        <input
                            type="password"
                            name="pin"
                            id="pin"
                            maxLength="4"
                            value={pin}
                            onChange={handlePinChange}
                            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-center tracking-[1em]"
                            placeholder="••••"
                        />
                    </div>
                    <div className="mt-6 flex items-center justify-between space-x-4">
                        <button
                            type="button"
                            onClick={handlePrevStep}
                            className="w-full bg-gray-200 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-300"
                        >
                            Back
                        </button>
                        <button
                            type="submit"
                            disabled={loading || pin.length !== 4}
                            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50"
                        >
                            {loading ? <Loader className="animate-spin h-5 w-5" /> : 'Confirm & Send'}
                        </button>
                    </div>
                </div>
            )}
        </form>
    </div>
  );
}
