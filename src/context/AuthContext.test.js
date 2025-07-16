// Test for the updated AuthContext
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { AuthProvider, useAuth } from '../context/AuthContext';

// Mock the SecureKeyManager
jest.mock('../utils/SecureKeyManager', () => ({
  SecureKeyManager: {
    getEncryptedKey: jest.fn(),
    encryptPrivateKey: jest.fn(),
    storeEncryptedKey: jest.fn(),
    decryptPrivateKey: jest.fn(),
    exportPublicKeyAsPem: jest.fn(),
    generateKeyPair: jest.fn(),
  }
}));

// Test component to access auth context
function TestComponent() {
  const auth = useAuth();
  
  return (
    <div>
      <div data-testid="loading">{auth.loading ? 'loading' : 'not loading'}</div>
      <div data-testid="authenticated">{auth.isAuthenticated ? 'authenticated' : 'not authenticated'}</div>
      <div data-testid="pin-set">{auth.pinIsSet ? 'pin set' : 'pin not set'}</div>
      <div data-testid="has-registration">{auth.hasCompletedRegistration() ? 'registered' : 'not registered'}</div>
    </div>
  );
}

describe('AuthContext with Cryptographic Authentication', () => {
  beforeEach(() => {
    // Clear localStorage before each test
    localStorage.clear();
    
    // Clear all mocks
    jest.clearAllMocks();
  });

  test('initial state shows not authenticated and not registered', async () => {
    const { SecureKeyManager } = require('../utils/SecureKeyManager');
    SecureKeyManager.getEncryptedKey.mockResolvedValue(null);
    
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('not loading');
    });

    expect(screen.getByTestId('authenticated')).toHaveTextContent('not authenticated');
    expect(screen.getByTestId('pin-set')).toHaveTextContent('pin not set');
    expect(screen.getByTestId('has-registration')).toHaveTextContent('not registered');
  });

  test('shows registered state when user has completed registration', async () => {
    const { SecureKeyManager } = require('../utils/SecureKeyManager');
    
    // Mock user has encrypted key and public key stored
    SecureKeyManager.getEncryptedKey.mockResolvedValue({ encrypted: 'mock-encrypted', salt: 'salt', iv: 'iv' });
    localStorage.setItem('userPublicKey', 'mock-public-key');
    localStorage.setItem('pinIsSet', 'true');
    
    render(
      <AuthProvider>
        <TestComponent />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('not loading');
    });

    expect(screen.getByTestId('pin-set')).toHaveTextContent('pin set');
    expect(screen.getByTestId('has-registration')).toHaveTextContent('registered');
    // Still not authenticated until keypair is unlocked
    expect(screen.getByTestId('authenticated')).toHaveTextContent('not authenticated');
  });

  test('login method works with correct PIN', async () => {
    const { SecureKeyManager } = require('../utils/SecureKeyManager');
    
    // Mock successful key decryption
    const mockPrivateKey = { type: 'private' };
    const mockPublicKey = { type: 'public' };
    
    SecureKeyManager.getEncryptedKey.mockResolvedValue({ encrypted: 'encrypted', salt: 'salt', iv: 'iv' });
    SecureKeyManager.decryptPrivateKey.mockResolvedValue(mockPrivateKey);
    
    // Mock Web Crypto API
    global.crypto = {
      subtle: {
        importKey: jest.fn().mockResolvedValue(mockPublicKey)
      }
    };
    
    global.atob = jest.fn().mockReturnValue('mock-decoded-key');
    
    localStorage.setItem('userPublicKey', 'mock-public-key-pem');
    localStorage.setItem('pinIsSet', 'true');

    let authContext;
    
    function TestComponentWithLogin() {
      authContext = useAuth();
      return <div data-testid="ready">ready</div>;
    }

    render(
      <AuthProvider>
        <TestComponentWithLogin />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('ready')).toBeInTheDocument();
    });

    // Test login
    const result = await authContext.login('123456');
    
    expect(result).toBe(true);
    expect(SecureKeyManager.decryptPrivateKey).toHaveBeenCalledWith(
      'encrypted',
      '123456',
      'salt',
      'iv'
    );
  });
});

export default {};
