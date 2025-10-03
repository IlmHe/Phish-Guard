// Production-safe logging utility
// Only logs in development mode, silent in production

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

export const logger = {
  log: (...args: any[]) => {
    if (!IS_PRODUCTION) {
      console.log(...args);
    }
  },

  warn: (...args: any[]) => {
    if (!IS_PRODUCTION) {
      console.warn(...args);
    }
  },

  error: (...args: any[]) => {
    // Always log errors, even in production (for debugging)
    console.error(...args);
  },

  debug: (...args: any[]) => {
    if (!IS_PRODUCTION) {
      console.debug(...args);
    }
  }
};

export default logger;