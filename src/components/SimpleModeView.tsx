import React from 'react';
import { ScanResult } from '../types';
import { ResourceScanResult } from '../services/resourceMonitor';

interface SimpleModeViewProps {
  scanResult: ScanResult;
  resourceScan: ResourceScanResult | null;
  url: string;
  certLoading: boolean;
  onToggleAdvanced: () => void;
  onCancel: () => void;
}

export const SimpleModeView: React.FC<SimpleModeViewProps> = ({
  scanResult,
  resourceScan,
  url,
  certLoading,
  onToggleAdvanced,
  onCancel
}) => {
  // Early return if scanResult is null (shouldn't happen due to parent component logic)
  if (!scanResult) return null;

  return (
    <div>
      {/* Quick Summary */}
      <div className="message is-info" style={{ marginBottom: '15px' }}>
        <div className="message-body">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span>🌐 Domain Age:</span>
            <span className={scanResult.domainInfo?.isRecentlyRegistered ? 'has-text-warning' : 'has-text-success'}>
              {scanResult.domainInfo?.domainAge ? `${scanResult.domainInfo.domainAge} days` : 'Unknown'}
              {scanResult.domainInfo?.isRecentlyRegistered && ' (New!)'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span>🔒 HTTPS:</span>
            <span className={url?.startsWith('https://') ? 'has-text-success' : 'has-text-warning'}>
              {url?.startsWith('https://') ? 'Secure' : 'Not Secure'}
            </span>
          </div>
          {url?.startsWith('https://') && (certLoading ? (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <span>📜 Certificate Age:</span>
              <span className="has-text-info">Loading...</span>
            </div>
          ) : scanResult.reputationScore?.certAnalysis && !scanResult.reputationScore.certAnalysis.error && scanResult.reputationScore.certAnalysis.issuer && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <span>📜 Certificate Age:</span>
              <span className={scanResult.reputationScore.certAnalysis.isVeryNewCert ? 'has-text-danger' : scanResult.reputationScore.certAnalysis.isNewCert ? 'has-text-warning' : 'has-text-success'}>
                {scanResult.reputationScore.certAnalysis.isVeryNewCert ?
                  `${scanResult.reputationScore.certAnalysis.certAgeHours}h (Very New!)` :
                  scanResult.reputationScore.certAnalysis.isNewCert ?
                  `${scanResult.reputationScore.certAnalysis.certAgeDays} days (Recent)` :
                  `${scanResult.reputationScore.certAnalysis.certAgeDays} days`
                }
              </span>
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span>📊 Overall Risk:</span>
            <span className={`has-text-${scanResult.reputationScore?.riskLevel === 'critical' || scanResult.reputationScore?.riskLevel === 'high' ? 'danger' : scanResult.reputationScore?.riskLevel === 'medium' ? 'warning' : 'success'}`}>
              {scanResult.reputationScore?.riskLevel?.toUpperCase() || 'CALCULATING...'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span>🔍 Database Status:</span>
            <span className={scanResult.supabaseStatus === 'found' ? 'has-text-danger' : 'has-text-success'}>
              {scanResult.supabaseStatus === 'found' ? 'Known Threat!' : 'Clean'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
            <span>📊 Resources Scanned:</span>
            <span className={(resourceScan?.suspiciousResources?.length || 0) > 0 ? 'has-text-warning' : 'has-text-success'}>
              {resourceScan?.totalResources || 0} total, {resourceScan?.suspiciousResources?.length || 0} suspicious
            </span>
          </div>
          {scanResult.domainInfo?.registrar && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <span>🏢 Registered by:</span>
              <span className="has-text-info">
                {scanResult.domainInfo.registrar}
              </span>
            </div>
          )}
          {scanResult.reputationScore?.apiResults && scanResult.reputationScore.apiResults.responseCount > 0 && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>🔍 Security Analysis:</span>
              <span className={`${scanResult.reputationScore.apiResults.consensus === 'malicious' ? 'has-text-danger' : scanResult.reputationScore.apiResults.consensus === 'suspicious' ? 'has-text-warning' : 'has-text-success'}`}>
                {scanResult.reputationScore.apiResults.consensus === 'malicious' ? 'Threats Found!' :
                 scanResult.reputationScore.apiResults.consensus === 'suspicious' ? 'Suspicious' :
                 'Clean'} ({scanResult.reputationScore.apiResults.responseCount} checks)
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Action buttons for simple mode */}
      <div style={{ textAlign: 'center' }}>
        <button
          className="button is-info is-light"
          onClick={onToggleAdvanced}
          style={{ marginRight: '10px' }}
        >
          🔧 View Technical Details
        </button>
        <button className="button is-light" onClick={onCancel}>
          Close
        </button>
      </div>
    </div>
  );
};