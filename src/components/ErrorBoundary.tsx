import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Phish Guard Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '100vh',
            background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '20px'
          }}
        >
          <div
            style={{
              background: 'rgba(255, 71, 87, 0.15)',
              border: '1px solid rgba(255, 71, 87, 0.3)',
              borderRadius: '12px',
              padding: '30px',
              maxWidth: '500px',
              textAlign: 'center'
            }}
          >
            <div style={{ fontSize: '3rem', marginBottom: '20px' }}>⚠️</div>
            <h2 style={{ color: '#ff4757', marginBottom: '15px', fontSize: '1.5rem' }}>
              Something Went Wrong
            </h2>
            <p style={{ color: '#ffffff', marginBottom: '20px', lineHeight: '1.6' }}>
              Phish Guard encountered an unexpected error. This might be due to a temporary issue.
            </p>

            {this.state.error && (
              <details style={{ marginBottom: '20px', textAlign: 'left' }}>
                <summary style={{ color: '#ffffff', cursor: 'pointer', marginBottom: '10px' }}>
                  Error Details
                </summary>
                <pre
                  style={{
                    background: 'rgba(0, 0, 0, 0.3)',
                    padding: '10px',
                    borderRadius: '6px',
                    color: '#ff4757',
                    fontSize: '12px',
                    overflow: 'auto',
                    maxHeight: '200px'
                  }}
                >
                  {this.state.error.message}
                </pre>
              </details>
            )}

            <button
              onClick={() => window.location.reload()}
              style={{
                background: '#ff4757',
                color: '#ffffff',
                border: 'none',
                padding: '12px 24px',
                borderRadius: '8px',
                fontSize: '14px',
                fontWeight: 'bold',
                cursor: 'pointer',
                transition: 'all 0.3s'
              }}
              onMouseOver={(e) => (e.currentTarget.style.background = '#ff3838')}
              onMouseOut={(e) => (e.currentTarget.style.background = '#ff4757')}
            >
              Reload Extension
            </button>

            <p style={{ color: '#a8a8a8', marginTop: '20px', fontSize: '13px' }}>
              If this problem persists, please{' '}
              <a
                href="https://github.com/IlmHe/Phish-Guard/issues"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#70a1ff', textDecoration: 'none' }}
              >
                report the issue
              </a>
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}