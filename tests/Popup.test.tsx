import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import Popup from '../src/Popup';
import { extractActualUrl, extractDomain } from '../src/utils/utils';
import browser from 'webextension-polyfill';
import { checkUrlInSupabase } from '../src/services/apiservice';
import { defaultSettings } from '../src/types';

jest.mock('webextension-polyfill', () => ({
  storage: { sync: { get: jest.fn() } }
}));
jest.mock('../src/services/apiservice', () => ({
  checkUrlInSupabase: jest.fn()
}));

jest.mock('../src/services/homographDetector', () => ({
  HomographDetector: {
    detectSuspiciousDomain: jest.fn().mockReturnValue({
      riskScore: 0,
      recommendation: 'safe',
      suspiciousPatterns: []
    })
  }
}));

describe('Popup component', () => {
  beforeEach(() => {
    (browser.storage.sync.get as jest.Mock).mockResolvedValue({ phishGuardSettings: defaultSettings });
  });

  it('displays scanned link and domain with not_found status', async () => {
    Object.defineProperty(window, 'location', {
      value: new URL('http://localhost/?url=https%3A%2F%2Fexample.com%2Fpath'),
      writable: true
    });
    (checkUrlInSupabase as jest.Mock).mockResolvedValue(false);
    render(<Popup />);
    expect(await screen.findByText(/Not found in our phishing databases/i)).toBeInTheDocument();
    expect(screen.getByText(/Link:/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'https://example.com/path' })).toHaveAttribute('href', 'https://example.com/path');
    expect(screen.getByText(/Domain:/)).toBeInTheDocument();
  });

  it('displays found status when URL in supabase', async () => {
    Object.defineProperty(window, 'location', {
      value: new URL('http://localhost/?url=https%3A%2F%2Fexample.com'),
      writable: true
    });
    (checkUrlInSupabase as jest.Mock).mockResolvedValue(true);
    render(<Popup />);
    expect(await screen.findByText(/Found in Phishing DB/i)).toBeInTheDocument();
  });
});
