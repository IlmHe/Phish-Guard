// jest.setup.ts
import '@testing-library/jest-dom';

// Mock webextension-polyfill with all necessary APIs
jest.mock('webextension-polyfill', () => ({
  storage: {
    sync: {
      get: jest.fn().mockResolvedValue({}),
      set: jest.fn().mockResolvedValue(undefined)
    }
  },
  runtime: {
    sendMessage: jest.fn().mockResolvedValue({}),
    onMessage: { addListener: jest.fn() },
    lastError: null,
    onInstalled: { addListener: jest.fn() }
  },
  contextMenus: {
    create: jest.fn((options, callback) => {
      if (callback) callback();
    }),
    onClicked: { addListener: jest.fn() }
  },
  windows: {
    create: jest.fn().mockResolvedValue({ id: 1 })
  }
}));

// Mock environment variables for testing
process.env.SUPABASE_URL = 'https://test.supabase.co';
process.env.SUPABASE_KEY = 'test-key';

// Create #root container before any React.createRoot calls
beforeAll(() => {
  const root = document.createElement('div');
  root.id = 'root';
  document.body.appendChild(root);
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});
