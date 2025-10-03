import React from 'react';

interface SafetyStatus {
  status: string;
  color: string;
  icon: string;
  message: string;
}

interface SafetyStatusCardProps {
  safetyStatus: SafetyStatus;
  isAdvancedMode: boolean;
}

export const SafetyStatusCard: React.FC<SafetyStatusCardProps> = ({ safetyStatus, isAdvancedMode }) => {
  return (
    <div
      className={`notification is-${safetyStatus.color}`}
      style={{
        textAlign: 'center',
        marginBottom: '20px',
        padding: '24px',
        borderRadius: '12px'
      }}
    >
      <div style={{ fontSize: '3rem', marginBottom: '12px' }}>{safetyStatus.icon}</div>
      <div style={{ fontSize: '1.3rem', fontWeight: 'bold', marginBottom: '8px', letterSpacing: '0.5px' }}>
        {safetyStatus.message}
      </div>
      {!isAdvancedMode && safetyStatus.status !== 'safe' && (
        <div style={{
          fontSize: '0.95rem',
          marginTop: '12px',
          padding: '10px',
          background: 'rgba(0, 0, 0, 0.2)',
          borderRadius: '8px'
        }}>
          <strong>Recommendation:</strong> {safetyStatus.status === 'dangerous' ? 'Do not proceed!' : 'Exercise caution'}
        </div>
      )}
    </div>
  );
};