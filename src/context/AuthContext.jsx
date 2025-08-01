// AuthContext.js - Updated for SecureCipher cryptographic authentication
import { createContext, useState, useContext, useEffect } from 'react';
import { SecureKeyManager } from '../utils/SecureKeyManager';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [unlockedKeyPair, setUnlockedKeyPair] = useState(null); // Holds the keypair in memory
  const [userPublicKey, setUserPublicKey] = useState(null); // Store user's public key
  const [pinIsSet, setPinIsSet] = useState(false); // Track if PIN is set
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [user, setUser] = useState(null); // Store user profile
  const [accounts, setAccounts] = useState([]); // Store user accounts
  const [transactions, setTransactions] = useState([]); // Store user transactions
  
  useEffect(() => {
    // Check authentication status based on encrypted key existence and PIN setup
    const checkAuthStatus = async () => {
      try {
        setLoading(true);
        
        // Check if user has an encrypted private key stored
        const encryptedKey = await SecureKeyManager.getEncryptedKey();
        const storedPublicKey = localStorage.getItem('userPublicKey');
        const pinStatus = localStorage.getItem('pinIsSet');
        
        if (encryptedKey && storedPublicKey && pinStatus === 'true') {
          // User has completed registration and PIN setup
          setPinIsSet(true);
          setUserPublicKey(storedPublicKey);
          // Authentication status depends on having unlocked keypair in memory
          setIsAuthenticated(!!unlockedKeyPair);
        } else if (encryptedKey && storedPublicKey) {
          // User registered but hasn't set PIN yet
          setUserPublicKey(storedPublicKey);
          setPinIsSet(false);
          setIsAuthenticated(false);
        } else {
          // User hasn't completed registration
          setPinIsSet(false);
          setIsAuthenticated(false);
        }
      } catch (error) {
        console.error('Error checking auth status:', error);
        setError('Failed to check authentication status');
        setIsAuthenticated(false);
        setPinIsSet(false);
      } finally {
        setLoading(false);
      }
    };
    
    checkAuthStatus();
  }, [unlockedKeyPair]); // Re-check when keypair changes
  
  // Set user data after login/registration and persist to localStorage
  const setUserData = (userData) => {
    setUser(userData.user || null);
    setAccounts(userData.accounts || []);
    setTransactions(userData.transactions || []);
    // Persist to localStorage (non-sensitive only)
    localStorage.setItem('userProfile', JSON.stringify(userData.user || null));
    localStorage.setItem('userAccounts', JSON.stringify(userData.accounts || []));
    localStorage.setItem('userTransactions', JSON.stringify(userData.transactions || []));
  };

  // Restore user data from localStorage on mount
  useEffect(() => {
    const storedUser = localStorage.getItem('userProfile');
    const storedAccounts = localStorage.getItem('userAccounts');
    const storedTransactions = localStorage.getItem('userTransactions');
    if (storedUser) setUser(JSON.parse(storedUser));
    if (storedAccounts) setAccounts(JSON.parse(storedAccounts));
    if (storedTransactions) setTransactions(JSON.parse(storedTransactions));
  }, []);
  
  // Login with PIN - unlock the stored encrypted keypair
  const login = async (pin, userData) => {
    try {
      setLoading(true);
      setError(null);
      
      // Validate PIN format before attempting decryption
      if (!pin || pin.length < 4) {
        throw new Error('PIN must be at least 4 digits long.');
      }
      
      // Attempt to unlock the encrypted private key with the PIN
      const encryptedKey = await SecureKeyManager.getEncryptedKey();
      if (!encryptedKey) {
        throw new Error('No encrypted key found. Please complete registration first.');
      }
      
      // Decrypt the private key
      const privateKey = await SecureKeyManager.decryptPrivateKey(
        encryptedKey.encrypted, 
        pin, 
        encryptedKey.salt, 
        encryptedKey.iv
      );
      
      console.log('DEBUG: Private key decryption successful');
      
      // Reconstruct the key pair with the public key from storage
      const storedPublicKey = userPublicKey || localStorage.getItem('userPublicKey');
      
      let publicKey;
      
      if (storedPublicKey) {
        console.log('DEBUG: Attempting to load stored public key...');
        try {
          // Parse PEM format public key
          const pemHeader = "-----BEGIN PUBLIC KEY-----";
          const pemFooter = "-----END PUBLIC KEY-----";
          const pemContents = storedPublicKey
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/\s/g, ''); // Remove all whitespace
          
          console.log('DEBUG: Extracted PEM contents length:', pemContents.length);
          
          const binaryDer = new Uint8Array(
            atob(pemContents)
              .split('')
              .map(c => c.charCodeAt(0))
          );
          
          console.log('DEBUG: Binary DER length:', binaryDer.length);
          
          publicKey = await window.crypto.subtle.importKey(
            'spki',
            binaryDer,
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['verify']
          );
          
          console.log('DEBUG: Stored public key import successful');
          
        } catch (publicKeyError) {
          console.warn('DEBUG: Stored public key import failed, regenerating from private key:', publicKeyError);
          publicKey = null; // Will regenerate below
        }
      }
      
      // Fallback: Generate public key from private key if stored key failed
      if (!publicKey) {
        console.log('DEBUG: Regenerating public key from private key...');
        try {
          // Export private key and re-import as key pair to get public key
          const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', privateKey);
          
          // Remove private key components to create public key JWK
          const publicKeyJwk = {
            kty: privateKeyJwk.kty,
            crv: privateKeyJwk.crv,
            x: privateKeyJwk.x,
            y: privateKeyJwk.y,
            use: 'sig',
            key_ops: ['verify']
          };
          
          publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            { name: 'ECDSA', namedCurve: 'P-384' },
            true,
            ['verify']
          );
          
          // Store the regenerated public key
          const newPublicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(publicKey);
          localStorage.setItem('userPublicKey', newPublicKeyPem);
          setUserPublicKey(newPublicKeyPem);
          
          console.log('DEBUG: Public key regenerated and stored successfully');
          
        } catch (regenError) {
          console.error('DEBUG: Failed to regenerate public key:', regenError);
          throw new Error('Unable to reconstruct public key. Please re-register.');
        }
      }
      
      const keyPair = { privateKey, publicKey };
      
      // Update authentication state
      setUnlockedKeyPair(keyPair);
      setIsAuthenticated(true);
      if (userData) setUserData(userData);
      
      console.log('Authentication successful');
      return true;
      
    } catch (error) {
      console.error('Login failed:', error);
      setError(error.message);
      setIsAuthenticated(false);
      setUnlockedKeyPair(null);
      throw error; // Re-throw for UI handling
    } finally {
      setLoading(false);
    }
  };
  
  // Register - store encrypted keypair and public key
  const register = async (keyPair, pin, userData) => {
    try {
      setLoading(true);
      setError(null);
      
      // Encrypt and store the private key
      const encryptedKeyData = await SecureKeyManager.encryptPrivateKey(keyPair.privateKey, pin);
      await SecureKeyManager.storeEncryptedKey(encryptedKeyData);
      
      // Store public key in localStorage for quick access
      const publicKeyPem = await SecureKeyManager.exportPublicKeyAsPem(keyPair.publicKey);
      localStorage.setItem('userPublicKey', publicKeyPem);
      
      setUserPublicKey(publicKeyPem);
      setUnlockedKeyPair(keyPair);
      markPinAsSet();
      setIsAuthenticated(true);
      if (userData) setUserData(userData);
      
      console.log('Registration completed successfully');
      return true;
      
    } catch (error) {
      console.error('Registration failed:', error);
      setError('Registration failed');
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  const logout = () => {
    // Clear all cryptographic data from memory and storage
    setUnlockedKeyPair(null);
    setIsAuthenticated(false);
    setUserPublicKey(null);
    setError(null);
    setUser(null);
    setAccounts([]);
    setTransactions([]);
       
    // Note: We keep the encrypted private key in IndexedDB so user can login again
    // To completely remove account, a separate deleteAccount method would be needed
    
    console.log('Logged out successfully');
  };

  const markPinAsSet = () => {
    localStorage.setItem('pinIsSet', 'true');
    setPinIsSet(true);
  };
  
  // Helper method to check if user has completed registration
  const hasCompletedRegistration = () => {
    return !!(userPublicKey && pinIsSet);
  };
  
  // Helper method to get current user's public key
  const getCurrentUserPublicKey = () => {
    return userPublicKey;
  };
  
  // Method to completely delete account and all cryptographic data
  const deleteAccount = async () => {
    try {
      // Clear all data from IndexedDB
      const dbRequest = indexedDB.deleteDatabase('secure-cipher-bank');
      
      // Clear localStorage
      localStorage.removeItem('userPublicKey');
      localStorage.removeItem('pinIsSet');
      localStorage.removeItem('userProfile');
      localStorage.removeItem('userAccounts');
      localStorage.removeItem('userTransactions');
      
      // Clear context state
      setUnlockedKeyPair(null);
      setIsAuthenticated(false);
      setUserPublicKey(null);
      setPinIsSet(false);
      setError(null);
      
      console.log('Account deleted successfully');
      return true;
    } catch (error) {
      console.error('Failed to delete account:', error);
      setError('Failed to delete account');
      return false;
    }
  };
  
  const value = {
    isAuthenticated,
    unlockedKeyPair,
    userPublicKey,
    loading,
    error,
    pinIsSet,
    login,
    register,
    logout,
    setUnlockedKeyPair,
    markPinAsSet,
    hasCompletedRegistration,
    getCurrentUserPublicKey,
    deleteAccount,
    user,
    accounts,
    transactions,
    setUserData,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
