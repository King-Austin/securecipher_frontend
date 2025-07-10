// AuthContext.js
import { createContext, useState, useContext, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [unlockedKeyPair, setUnlockedKeyPair] = useState(null); // Holds the keypair in memory
  const [pinIsSet, setPinIsSet] = useState(false); // New state to track if PIN is set
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    // This effect checks for a refresh token to re-authenticate the user on page load
    const reAuth = async () => {
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          // TODO: Implement token refresh logic here
          // For now, we just mark as authenticated if a token exists
          setIsAuthenticated(true); 
        } catch (err) {
          // If refresh fails, clear tokens
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          setIsAuthenticated(false);
        }
      }
      setLoading(false);
    };
    reAuth();
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
    // Clear everything on logout
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('pinIsSet'); // Clear PIN status on logout
    setUnlockedKeyPair(null); // Clear the in-memory key
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
