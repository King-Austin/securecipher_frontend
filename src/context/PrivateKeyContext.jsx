import React, { createContext, useContext, useState, useCallback } from 'react';
import { SecureKeyManager } from '../utils/SecureKeyManager';

const PrivateKeyContext = createContext();

export function PrivateKeyProvider({ children }) {
  const [privateKey, setPrivateKey] = useState(null);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState(null);

  // Show/hide PIN modal
  const [showPinModal, setShowPinModal] = useState(false);
  const [pendingResolve, setPendingResolve] = useState(null);

  // Unlock private key with PIN
  const unlockPrivateKey = useCallback(async (pin) => {
    setIsUnlocking(true);
    setUnlockError(null);
    try {
      const key = await SecureKeyManager.getPrivateKey(pin);
      setPrivateKey(key);
      setShowPinModal(false);
      if (pendingResolve) pendingResolve(key);
      setPendingResolve(null);
      return key;
    } catch (err) {
      setUnlockError(err.message || 'Failed to unlock private key');
      throw err;
    } finally {
      setIsUnlocking(false);
    }
  }, [pendingResolve]);

  // Request private key (show PIN modal if not unlocked)
  const requestPrivateKey = useCallback(() => {
    if (privateKey) return Promise.resolve(privateKey);
    setShowPinModal(true);
    return new Promise((resolve) => setPendingResolve(() => resolve));
  }, [privateKey]);

  // Clear private key from memory
  const clearPrivateKey = useCallback(() => {
    setPrivateKey(null);
  }, []);

  return (
    <PrivateKeyContext.Provider value={{ privateKey, requestPrivateKey, clearPrivateKey, isUnlocking, unlockPrivateKey, unlockError, showPinModal, setShowPinModal }}>
      {children}
    </PrivateKeyContext.Provider>
  );
}

export function usePrivateKey() {
  return useContext(PrivateKeyContext);
}
