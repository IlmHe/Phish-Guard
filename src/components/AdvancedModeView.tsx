import React from 'react';
import { ScanResult } from '../types';
import { ResourceScanResult } from '../services/resourceMonitor';
import { SuspiciousDomainAnalysis } from '../services/homographDetector';
import { ReputationService } from '../services/reputationService';
import { DomainInfoService } from '../services/domainInfoService';
import { SitemapService, SitemapResult } from '../services/sitemapService';

interface AdvancedModeViewProps {
  scanResult: ScanResult;
  resourceScan: ResourceScanResult | null;
  homographAnalysis: SuspiciousDomainAnalysis | null;
  url: string;
  domain: string;
  sitemapLoading: boolean;
  certLoading: boolean;
  onCancel: () => void;
}

export const AdvancedModeView: React.FC<AdvancedModeViewProps> = ({
  scanResult,
  resourceScan,
  homographAnalysis,
  url,
  domain,
  sitemapLoading,
  certLoading,
  onCancel
}) => {
  // Early return if scanResult is null (shouldn't happen due to parent component logic)
  if (!scanResult) return null;

  return (
    <div>
      {/* Homograph Analysis */}
      {homographAnalysis && (
        <div className={`message ${homographAnalysis.recommendation === 'dangerous' ? 'is-danger' : homographAnalysis.recommendation === 'caution' ? 'is-warning' : 'is-success'}`}>
          <div className="message-header">
            <p>Domain Security Analysis</p>
          </div>
          <div className="message-body">
            <p><strong>Risk Level:</strong> {homographAnalysis.recommendation.toUpperCase()} (Score: {homographAnalysis.riskScore}/100)</p>
            {homographAnalysis.suspiciousPatterns.length > 0 && (
              <p><strong>Suspicious patterns:</strong> {homographAnalysis.suspiciousPatterns.join(', ')}</p>
            )}
            {homographAnalysis.recommendation === 'dangerous' && (
              <p className="has-text-danger"><strong>⚠️ Warning:</strong> This domain shows high risk patterns that may indicate phishing or impersonation attempts.</p>
            )}
            {homographAnalysis.recommendation === 'caution' && (
              <p className="has-text-warning"><strong>⚠️ Caution:</strong> This domain shows some suspicious patterns. Please verify before proceeding.</p>
            )}
          </div>
        </div>
      )}

      {/* Comprehensive Reputation Analysis */}
      {scanResult.reputationScore && (
        <div className={`message ${ReputationService.getRiskClass(scanResult.reputationScore.riskLevel)}`}>
          <div className="message-header">
            <p>🛡️ Comprehensive Security Analysis</p>
          </div>
          <div className="message-body">
            <p><strong>Risk Level:</strong> {scanResult.reputationScore.riskLevel.toUpperCase()} (Score: {scanResult.reputationScore.overall}/100)</p>
            <p><strong>Confidence:</strong> {scanResult.reputationScore.confidence}%</p>
            <p>{ReputationService.getRiskDescription(scanResult.reputationScore.riskLevel, scanResult.reputationScore.overall)}</p>

            {/* Threat Types */}
            {scanResult.reputationScore.threatTypes.length > 0 && (
              <div className="mt-3">
                <strong>🚨 Detected Threats:</strong>
                <ul className="ml-4">
                  {scanResult.reputationScore.threatTypes.map((threat, index) => (
                    <li key={index} className={`has-text-${threat.severity === 'critical' ? 'danger' : threat.severity === 'high' ? 'danger' : threat.severity === 'medium' ? 'warning' : 'info'}`}>
                      • {threat.type.replace(/_/g, ' ').toUpperCase()}: {threat.description}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Risk Factors */}
            {scanResult.reputationScore.factors.length > 0 && (
              <details className="mt-3">
                <summary className="has-text-weight-semibold" style={{ cursor: 'pointer' }}>
                  🔍 View {scanResult.reputationScore.factors.length} Risk Factor(s)
                </summary>
                <div className="mt-2">
                  {scanResult.reputationScore.factors.map((factor, index) => (
                    <div key={index} className="mb-2 p-2" style={{ backgroundColor: 'rgba(0,0,0,0.05)', borderRadius: '4px' }}>
                      <strong>{factor.category}</strong> (+{factor.impact} points)
                      <br />
                      <small>{factor.description}</small>
                      <br />
                      <small className="has-text-grey"><em>{factor.evidence}</em></small>
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>
        </div>
      )}

      {/* External Security Analysis Tools */}
      <div className="message is-info">
        <div className="message-header">
          <p>🔍 External Security & Site Analysis</p>
        </div>
        <div className="message-body">
          <p className="mb-3"><strong>Security Analysis Tools:</strong></p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <a
              href={scanResult.virusTotalUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="button is-small is-fullwidth is-link"
              style={{ justifyContent: 'flex-start' }}
            >
              🛡️ VirusTotal - Multi-engine malware scanner
            </a>
            <a
              href={`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="button is-small is-fullwidth is-link"
              style={{ justifyContent: 'flex-start' }}
            >
              🔒 Google Safe Browsing - Threat detection
            </a>
            <a
              href={`https://urlscan.io/search/#${encodeURIComponent(domain)}`}
              target="_blank"
              rel="noopener noreferrer"
              className="button is-small is-fullwidth is-link"
              style={{ justifyContent: 'flex-start' }}
            >
              🔎 URLScan.io - Website scanner
            </a>
          </div>

          <p className="mt-3 mb-2"><strong>Site Structure:</strong></p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {scanResult.robotsUrl && (
              <a
                href={scanResult.robotsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="button is-small is-fullwidth is-info is-light"
                style={{ justifyContent: 'flex-start' }}
              >
                📄 View robots.txt
              </a>
            )}
            {sitemapLoading ? (
              <button className="button is-small is-fullwidth is-loading is-light" disabled>
                🗺️ Finding Sitemaps...
              </button>
            ) : scanResult.sitemapResult && scanResult.sitemapResult.found ? (
              <div className="dropdown is-hoverable" style={{ width: '100%' }}>
                <div className="dropdown-trigger" style={{ width: '100%' }}>
                  <button className="button is-small is-fullwidth is-success is-light" style={{ justifyContent: 'space-between' }}>
                    <span>🗺️ Found {scanResult.sitemapResult.urls.length} Sitemap(s)</span>
                    <span className="icon is-small">
                      <i className="fas fa-angle-down"></i>
                    </span>
                  </button>
                </div>
                <div className="dropdown-menu" style={{ width: '100%' }}>
                  <div className="dropdown-content">
                    <div className="dropdown-item">
                      <small className="has-text-grey">
                        Method: {scanResult.sitemapResult.method} |
                        {SitemapService.generateSummary(scanResult.sitemapResult)}
                      </small>
                    </div>
                    <hr className="dropdown-divider" />
                    {scanResult.sitemapResult.urls.map((sitemapUrl: string, index: number) => (
                      <a
                        key={index}
                        href={sitemapUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="dropdown-item"
                      >
                        📄 Sitemap {index + 1}
                      </a>
                    ))}
                  </div>
                </div>
              </div>
            ) : scanResult.sitemapUrl ? (
              <a
                href={scanResult.sitemapUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="button is-small is-fullwidth is-warning is-light"
                style={{ justifyContent: 'flex-start' }}
              >
                🔍 Search for Sitemap
              </a>
            ) : null}
          </div>
        </div>
      </div>

      {/* Resource Security Analysis */}
      {resourceScan && (
        <div className={`message ${(resourceScan?.riskScore || 0) >= 50 ? 'is-danger' : (resourceScan?.riskScore || 0) >= 30 ? 'is-warning' : 'is-info'}`}>
          <div className="message-header">
            <p>🔗 Resource Security Analysis</p>
          </div>
          <div className="message-body">
            <p><strong>Risk Score:</strong> <span className={(resourceScan?.riskScore || 0) >= 50 ? 'has-text-danger' : (resourceScan?.riskScore || 0) >= 30 ? 'has-text-warning' : 'has-text-success'}>
              {resourceScan?.riskScore || 0}/100
            </span></p>
            <p><strong>Summary:</strong> {resourceScan.summary}</p>

            <div className="mt-3">
              <p><strong>📊 Scan Results:</strong></p>
              <ul className="ml-4">
                <li>• Total Resources: {resourceScan.totalResources}</li>
                <li>• External Domains: {resourceScan.externalDomains.length}</li>
                <li>• Suspicious Resources: <span className={resourceScan.suspiciousResources.length > 0 ? 'has-text-danger' : 'has-text-success'}>
                  {resourceScan.suspiciousResources.length}
                </span></li>
                <li>• Mixed Content Warnings: <span className={resourceScan.mixedContentWarnings.length > 0 ? 'has-text-warning' : 'has-text-success'}>
                  {resourceScan.mixedContentWarnings.length}
                </span></li>
              </ul>
            </div>

            {/* Suspicious Resources Details */}
            {resourceScan.suspiciousResources.length > 0 && (() => {
              // Deduplicate resources by URL
              const seen = new Set<string>();
              const uniqueResources = resourceScan.suspiciousResources.filter(resource => {
                if (seen.has(resource.url)) return false;
                seen.add(resource.url);
                return true;
              });

              return (
                <details className="mt-3">
                  <summary className="has-text-weight-semibold" style={{ cursor: 'pointer' }}>
                    🚨 View {uniqueResources.length} Suspicious Resource(s)
                  </summary>
                  <div className="mt-2">
                    {uniqueResources.map((resource, index) => (
                    <div key={index} className="mb-2 p-2" style={{ backgroundColor: 'rgba(255,0,0,0.05)', borderRadius: '4px', border: '1px solid rgba(255,0,0,0.2)' }}>
                      <strong className={`has-text-${resource.riskLevel === 'critical' ? 'danger' : resource.riskLevel === 'high' ? 'danger' : resource.riskLevel === 'medium' ? 'warning' : 'info'}`}>
                        {resource.type.toUpperCase()} - {resource.riskLevel.toUpperCase()} Risk
                      </strong>
                      <br />
                      <small><strong>URL:</strong> {resource.url}</small>
                      <br />
                      <small><strong>Domain:</strong> {resource.domain}</small>
                      <br />
                      <small><strong>Reasons:</strong> {resource.reasons.join(', ')}</small>
                    </div>
                  ))}
                </div>
              </details>
              );
            })()}

            {/* Mixed Content Warnings */}
            {resourceScan.mixedContentWarnings.length > 0 && (
              <details className="mt-3">
                <summary className="has-text-weight-semibold" style={{ cursor: 'pointer' }}>
                  ⚠️ View {resourceScan.mixedContentWarnings.length} Mixed Content Warning(s)
                </summary>
                <div className="mt-2">
                  {resourceScan.mixedContentWarnings.map((warning, index) => (
                    <div key={index} className="mb-2 p-2" style={{ backgroundColor: 'rgba(255,165,0,0.05)', borderRadius: '4px', border: '1px solid rgba(255,165,0,0.2)' }}>
                      <strong className="has-text-warning">{warning.description}</strong>
                      <br />
                      <small><strong>Insecure URL:</strong> {warning.insecureUrl}</small>
                    </div>
                  ))}
                </div>
              </details>
            )}

            {/* External Domains */}
            {resourceScan.externalDomains.length > 0 && (
              <details className="mt-3">
                <summary className="has-text-weight-semibold" style={{ cursor: 'pointer' }}>
                  🌐 View {resourceScan.externalDomains.length} External Domain(s)
                </summary>
                <div className="mt-2">
                  <ul className="ml-4">
                    {resourceScan.externalDomains.map((domain, index) => (
                      <li key={index} className="mb-1">• {domain}</li>
                    ))}
                  </ul>
                </div>
              </details>
            )}
          </div>
        </div>
      )}

      {/* Domain Age & Certificate Analysis */}
      {(scanResult.domainInfo || scanResult.certificateInfo) && (
        <div className="message is-info">
          <div className="message-header">
            <p>🕒 Domain & Certificate Analysis</p>
          </div>
          <div className="message-body">
            {/* Domain Information */}
            {scanResult.domainInfo && (
              <div className="mb-3">
                <strong>Domain Information:</strong>
                {scanResult.domainInfo.domainAge !== undefined && (
                  <p>
                    📅 Domain Age: <span className={scanResult.domainInfo.isRecentlyRegistered ? 'has-text-danger' : 'has-text-success'}>
                      {scanResult.domainInfo.domainAge} days old
                      {scanResult.domainInfo.isRecentlyRegistered && ' ⚠️ Recently registered!'}
                    </span>
                  </p>
                )}
                {scanResult.domainInfo.registrationDate && (
                  <p>📝 Registered: {new Date(scanResult.domainInfo.registrationDate).toLocaleDateString()}</p>
                )}
                {scanResult.domainInfo.registrar && (
                  <p>🏢 Registrar: {scanResult.domainInfo.registrar}</p>
                )}
                {scanResult.domainInfo.whoisUrl && (
                  <p>
                    <a href={scanResult.domainInfo.whoisUrl} target="_blank" rel="noopener noreferrer" className="button is-small is-info is-light">
                      🔍 View Full WHOIS
                    </a>
                  </p>
                )}
              </div>
            )}

            {/* Certificate Information */}
            {scanResult.certificateInfo && (
              <div>
                <strong>SSL Certificate:</strong>
                {url.startsWith('https://') ? (
                  <>
                    <p>🔒 HTTPS Enabled</p>
                    {certLoading ? (
                      <p className="has-text-info">📜 Checking certificate age...</p>
                    ) : scanResult.reputationScore?.certAnalysis && !scanResult.reputationScore.certAnalysis.error && scanResult.reputationScore.certAnalysis.issuer && (
                      <>
                        <p>
                          📜 Certificate Age: <span className={scanResult.reputationScore.certAnalysis.isVeryNewCert ? 'has-text-danger' : scanResult.reputationScore.certAnalysis.isNewCert ? 'has-text-warning' : 'has-text-success'}>
                            {scanResult.reputationScore.certAnalysis.isVeryNewCert ?
                              `${scanResult.reputationScore.certAnalysis.certAgeHours} hours (Very New! ⚠️)` :
                              scanResult.reputationScore.certAnalysis.isNewCert ?
                              `${scanResult.reputationScore.certAnalysis.certAgeDays} days (Recent)` :
                              `${scanResult.reputationScore.certAnalysis.certAgeDays} days`
                            }
                          </span>
                        </p>
                        <p>
                          🏢 Issuer: {scanResult.reputationScore.certAnalysis.issuer.split(',')[0]}
                          {scanResult.reputationScore.certAnalysis.isFreeCA && <span className="has-text-info"> (Free CA)</span>}
                        </p>
                        {scanResult.reputationScore.certAnalysis.notBefore && (
                          <p>📅 Issued: {new Date(scanResult.reputationScore.certAnalysis.notBefore).toLocaleDateString()}</p>
                        )}
                      </>
                    )}
                    <p>
                      <a href={`https://www.ssllabs.com/ssltest/analyze.html?d=${domain}`} target="_blank" rel="noopener noreferrer" className="button is-small is-info is-light">
                        🛡️ SSL Labs Test
                      </a>
                    </p>
                  </>
                ) : (
                  <p className="has-text-warning">⚠️ No HTTPS encryption</p>
                )}
              </div>
            )}

            {/* Risk Assessment */}
            {(() => {
              const riskAssessment = DomainInfoService.calculateRiskScore(scanResult.domainInfo, scanResult.certificateInfo);
              if (riskAssessment.factors.length > 0) {
                return (
                  <div className="mt-3">
                    <strong>⚠️ Risk Factors:</strong>
                    <ul className="ml-4">
                      {riskAssessment.factors.map((factor, index) => (
                        <li key={index} className="has-text-warning">• {factor}</li>
                      ))}
                    </ul>
                    <p><strong>Risk Score:</strong> <span className={riskAssessment.score > 50 ? 'has-text-danger' : riskAssessment.score > 25 ? 'has-text-warning' : 'has-text-success'}>
                      {riskAssessment.score}/100
                    </span></p>
                  </div>
                );
              }
              return null;
            })()}
          </div>
        </div>
      )}

      {/* Supabase Status */}
      <>
        {scanResult.supabaseStatus === 'found' && <p className="has-text-danger"><strong>Database Status:</strong> Found in Phishing DB (Supabase)</p>}
        {scanResult.supabaseStatus === 'not_found' && <p className="has-text-success"><strong>Database Status:</strong> Not found in our phishing databases.</p>}
        {scanResult.supabaseStatus === 'error' && <p className="has-text-warning"><strong>Database Status:</strong> Error checking Phishing DB: {scanResult.error}</p>}
        {scanResult.supabaseStatus === 'not_checked' && <p><strong>Database Status:</strong> Checking Supabase...</p>}
      </>

      <button className="button is-light is-fullwidth" onClick={onCancel} style={{ marginTop: '20px' }}>Close</button>
    </div>
  );
};