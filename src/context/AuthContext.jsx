// AuthContext.js
import { createContext, useState, useContext, useEffect } from 'react';
import secureApi from '../services/secureApi'; // Import the secureApi service

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [unlockedKeyPair, setUnlockedKeyPair] = useState(null); // Holds the keypair in memory
  const [pinIsSet, setPinIsSet] = useState(false); // New state to track if PIN is set
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    // This effect checks for a refresh token to determine initial auth state
    const checkAuthStatus = () => {
      const token = localStorage.getItem('refreshToken');
      if (token) {
        setIsAuthenticated(true);
      }
      setLoading(false);
    };
    checkAuthStatus();
  }, []);
  
  useEffect(() => {
    // Check if PIN is marked as set in localStorage
    const checkPinStatus = () => {
      const pinStatus = localStorage.getItem('pinIsSet');
      if (pinStatus === 'true') {
        setPinIsSet(true);
      }
    };
    checkPinStatus();
    setLoading(false);
  }, []);
  
  const login = (accessToken, refreshToken) => {
    // Store tokens and set auth state
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    setIsAuthenticated(true);
    setError(null);
  };
  
  const logout = () => {
    // Use the logout function from secureApi which handles clearing local storage
    // and redirecting.
    secureApi.logout(); 
    
    // Also update local context state
    setUnlockedKeyPair(null);
    setIsAuthenticated(false);
    setPinIsSet(false);
    setError(null);
  };

  const markPinAsSet = () => {
    localStorage.setItem('pinIsSet', 'true');
    setPinIsSet(true);
  };
  
  const value = {
    isAuthenticated,
    unlockedKeyPair,
    loading,
    error,
    pinIsSet,
    login,
    logout,
    setUnlockedKeyPair, // Expose this to be used by the Login page
    markPinAsSet,
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
