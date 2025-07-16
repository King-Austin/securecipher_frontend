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
  
  // Login with PIN - unlock the stored encrypted keypair
  const login = async (pin) => {
    try {
      setLoading(true);
      setError(null);
      
      // Attempt to unlock the encrypted private key with the PIN
      const encryptedKey = await SecureKeyManager.getEncryptedKey();
      if (!encryptedKey) {
        throw new Error('No encrypted key found. Please complete registration first.');
      }
      
      const privateKey = await SecureKeyManager.decryptPrivateKey(
        encryptedKey.encrypted, 
        pin, 
        encryptedKey.salt, 
        encryptedKey.iv
      );
      
      // Generate public key from private key for verification
      const keyPair = {
        privateKey,
        publicKey: await window.crypto.subtle.importKey(
          'spki',
          new Uint8Array(atob(userPublicKey || localStorage.getItem('userPublicKey')).split('').map(c => c.charCodeAt(0))),
          { name: 'ECDSA', namedCurve: 'P-384' },
          true,
          ['verify']
        )
      };
      
      setUnlockedKeyPair(keyPair);
      setIsAuthenticated(true);
      
      console.log('Successfully authenticated with cryptographic keys');
      return true;
      
    } catch (error) {
      console.error('Login failed:', error);
      setError('Invalid PIN or authentication failed');
      setIsAuthenticated(false);
      setUnlockedKeyPair(null);
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Register - store encrypted keypair and public key
  const register = async (keyPair, pin) => {
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
    setPinIsSet(false);
    setError(null);
    
    // Clear stored data (but keep encrypted keys for re-login)
    localStorage.removeItem('userPublicKey');
    localStorage.removeItem('pinIsSet');
    
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
    login, // Now takes PIN instead of tokens
    register, // New method for registration
    logout,
    setUnlockedKeyPair, // Keep for compatibility
    markPinAsSet,
    hasCompletedRegistration,
    getCurrentUserPublicKey,
    deleteAccount,
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
