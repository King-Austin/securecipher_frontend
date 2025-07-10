import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ChevronRight, ChevronLeft, Shield, AlertCircle, Loader2 } from 'lucide-react';
import { secureApi } from '../services/secureApi';
import { SecureKeyManager } from '../utils/SecureKeyManager';

const steps = ['Personal Information', 'Account Security', 'Verification'];

export default function Registration() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    username: '',
    pin: '',
    confirm_pin: '',
    phone: '',
    bvn: '',
    nin: '',
    date_of_birth: '',
    address: '',
    occupation: '',
  });
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionError, setSubmissionError] = useState('');
  
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    // Clear error when field is updated
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: null }));
    }
  };

  const validateStep = () => {
    let stepErrors = {};
    let isValid = true;
    
    if (currentStep === 0) {
      // Validate personal information
      if (!formData.first_name.trim()) {
        stepErrors.first_name = 'First name is required';
        isValid = false;
      }
      
      if (!formData.last_name.trim()) {
        stepErrors.last_name = 'Last name is required';
        isValid = false;
      }
      
      if (!formData.email.trim()) {
        stepErrors.email = 'Email is required';
        isValid = false;
      } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
        stepErrors.email = 'Email is invalid';
        isValid = false;
      }
      
      if (!formData.phone.trim()) {
        stepErrors.phone = 'Phone number is required';
        isValid = false;
      }
    } else if (currentStep === 1) {
      // Validate account security
      if (!formData.username.trim()) {
        stepErrors.username = 'Username is required';
        isValid = false;
      }
      
      if (!formData.pin) {
        stepErrors.pin = 'A 6-digit PIN is required';
        isValid = false;
      } else if (!/^\d{6}$/.test(formData.pin)) {
        stepErrors.pin = 'PIN must be exactly 6 digits';
        isValid = false;
      }
      
      if (formData.pin !== formData.confirm_pin) {
        stepErrors.confirm_pin = 'PINs do not match';
        isValid = false;
      }
    } else if (currentStep === 2) {
      // Validate verification info
      if (!formData.bvn.trim()) {
        stepErrors.bvn = 'BVN is required';
        isValid = false;
      } else if (!/^\d{11}$/.test(formData.bvn)) {
        stepErrors.bvn = 'BVN must be 11 digits';
        isValid = false;
      }
      
      if (!formData.nin.trim()) {
        stepErrors.nin = 'NIN is required';
        isValid = false;
      } else if (!/^\d{11}$/.test(formData.nin)) {
        stepErrors.nin = 'NIN must be 11 digits';
        isValid = false;
      }
      
      if (!formData.date_of_birth) {
        stepErrors.date_of_birth = 'Date of birth is required';
        isValid = false;
      }
      
      if (!formData.address.trim()) {
        stepErrors.address = 'Address is required';
        isValid = false;
      }
      
      if (!formData.occupation.trim()) {
        stepErrors.occupation = 'Occupation is required';
        isValid = false;
      }
    }
    
    setErrors(stepErrors);
    return isValid;
  };

  const handleNext = () => {
    if (validateStep()) {
      setCurrentStep(prev => Math.min(prev + 1, steps.length - 1));
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => Math.max(prev - 1, 0));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateStep()) {
      return;
    }

    setIsSubmitting(true);
    setSubmissionError('');

    try {
      // 1. Generate cryptographic key pair
      const keyPair = await SecureKeyManager.generateKeyPair();
      const publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);

      // 2. Encrypt the private key with the user's PIN
      const encryptedKey = await SecureKeyManager.encryptPrivateKey(keyPair.privateKey, formData.pin);

      // 3. Store the encrypted key securely in IndexedDB
      await SecureKeyManager.storeEncryptedKey(encryptedKey);

      // 4. Prepare the registration payload for the backend
      const registrationPayload = {
        user_profile: {
          first_name: formData.first_name,
          last_name: formData.last_name,
          email: formData.email,
          phone: formData.phone,
          date_of_birth: formData.date_of_birth,
          address: formData.address,
          occupation: formData.occupation,
        },
        kyc_data: {
          bvn: formData.bvn,
          nin: formData.nin,
        },
        auth_data: {
          username: formData.username,
          public_key: publicKeyPem,
        }
      };

      // 5. Send the data through the secure gateway
      const response = await secureApi('register', registrationPayload);

      console.log('Registration successful:', response);
      
      // On success, navigate to the login page to use the new key
      navigate('/login');

    } catch (err) {
      console.error('Registration failed:', err);
      setSubmissionError(err.message || 'An unexpected error occurred. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case 0:
        return <Step1 formData={formData} handleChange={handleChange} errors={errors} />;
      case 1:
        return <Step2 formData={formData} handleChange={handleChange} errors={errors} />;
      case 2:
        return <Step3 formData={formData} handleChange={handleChange} errors={errors} />;
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl w-full space-y-8 bg-white p-10 rounded-xl shadow-lg">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Create Your Secure Account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Step {currentStep + 1} of {steps.length}: {steps[currentStep]}
          </p>
        </div>

        {/* Progress Bar */}
        <div className="w-full">
          <div className="flex justify-between mb-1">
            {steps.map((step, index) => (
              <div key={step} className={`text-xs font-medium ${index <= currentStep ? 'text-green-700' : 'text-gray-400'}`}>
                {step}
              </div>
            ))}
          </div>
          <div className="bg-gray-200 rounded-full h-2.5">
            <div className="bg-green-600 h-2.5 rounded-full" style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}></div>
          </div>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          {renderStep()}

          {submissionError && (
            <div className="flex items-center space-x-2 text-sm text-red-600 p-3 bg-red-50 rounded-md">
              <AlertCircle className="h-5 w-5" />
              <p>{submissionError}</p>
            </div>
          )}

          <div className="flex justify-between items-center pt-6">
            {currentStep > 0 ? (
              <button
                type="button"
                onClick={handleBack}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                <ChevronLeft className="h-5 w-5 mr-2" />
                Back
              </button>
            ) : <div />}

            {currentStep < steps.length - 1 ? (
              <button
                type="button"
                onClick={handleNext}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
              >
                Next
                <ChevronRight className="h-5 w-5 ml-2" />
              </button>
            ) : (
              <button
                type="submit"
                disabled={isSubmitting}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-400"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="animate-spin h-5 w-5 mr-2" />
                    Creating Account...
                  </>
                ) : (
                  <>
                    <Shield className="h-5 w-5 mr-2" />
                    Complete Registration
                  </>
                )}
              </button>
            )}
          </div>
        </form>
        <p className="mt-4 text-center text-sm text-gray-600">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-green-600 hover:text-green-500">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}

// --- Child Components for Steps ---

function Step1({ formData, handleChange, errors }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <InputField name="first_name" label="First Name" value={formData.first_name} onChange={handleChange} error={errors.first_name} />
      <InputField name="last_name" label="Last Name" value={formData.last_name} onChange={handleChange} error={errors.last_name} />
      <InputField name="email" type="email" label="Email Address" value={formData.email} onChange={handleChange} error={errors.email} />
      <InputField name="phone" label="Phone Number" value={formData.phone} onChange={handleChange} error={errors.phone} />
      <InputField name="date_of_birth" type="date" label="Date of Birth" value={formData.date_of_birth} onChange={handleChange} error={errors.date_of_birth} isRequired={false} />
      <InputField name="address" label="Residential Address" value={formData.address} onChange={handleChange} error={errors.address} isRequired={false} />
      <InputField name="occupation" label="Occupation" value={formData.occupation} onChange={handleChange} error={errors.occupation} isRequired={false} />
    </div>
  );
}

function Step2({ formData, handleChange, errors }) {
  return (
    <div className="space-y-6">
      <InputField name="username" label="Username" value={formData.username} onChange={handleChange} error={errors.username} />
      <InputField name="pin" type="password" label="6-Digit Security PIN" value={formData.pin} onChange={handleChange} error={errors.pin} maxLength={6} />
      <InputField name="confirm_pin" type="password" label="Confirm PIN" value={formData.confirm_pin} onChange={handleChange} error={errors.confirm_pin} maxLength={6} />
    </div>
  );
}

function Step3({ formData, handleChange, errors }) {
  return (
    <div className="space-y-6">
      <InputField name="bvn" label="Bank Verification Number (BVN)" value={formData.bvn} onChange={handleChange} error={errors.bvn} maxLength={11} />
      <InputField name="nin" label="National Identification Number (NIN)" value={formData.nin} onChange={handleChange} error={errors.nin} maxLength={11} />
    </div>
  );
}

function InputField({ name, label, type = 'text', value, onChange, error, isRequired = true, maxLength }) {
  return (
    <div>
      <label htmlFor={name} className="block text-sm font-medium text-gray-700">
        {label}
      </label>
      <div className="mt-1">
        <input
          id={name}
          name={name}
          type={type}
          required={isRequired}
          value={value}
          onChange={onChange}
          maxLength={maxLength}
          className={`appearance-none block w-full px-3 py-2 border ${error ? 'border-red-500' : 'border-gray-300'} rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-green-500 focus:border-green-500 sm:text-sm`}
        />
      </div>
      {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
    </div>
  );
}
