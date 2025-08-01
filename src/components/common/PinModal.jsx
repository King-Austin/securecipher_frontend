import React, { useState } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';

export default function PinModal({ onUnlock, onCancel, isUnlocking, error }) {
  const [pin, setPin] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (pin.length >= 4) {
      onUnlock(pin);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-40 z-50">
      <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-xs">
        <h2 className="text-lg font-semibold mb-4 text-center">Unlock Private Key</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            className="w-full border rounded px-3 py-2 text-lg"
            placeholder="Enter your PIN"
            value={pin}
            onChange={e => setPin(e.target.value.replace(/[^0-9]/g, ''))}
            minLength={4}
            maxLength={6}
            autoFocus
            disabled={isUnlocking}
          />
          {error && (
            <div className="flex items-center text-red-600 text-sm">
              <AlertCircle className="h-4 w-4 mr-1" />
              {error}
            </div>
          )}
          <div className="flex justify-between items-center">
            <button
              type="button"
              className="text-gray-500 hover:text-gray-700"
              onClick={onCancel}
              disabled={isUnlocking}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 flex items-center"
              disabled={isUnlocking || pin.length < 4}
            >
              {isUnlocking ? <Loader2 className="animate-spin h-5 w-5 mr-2" /> : null}
              Unlock
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
