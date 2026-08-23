import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ShieldAlert, CheckCircle, ChevronDown, ChevronUp, AlertCircle, Ban } from 'lucide-react';

function ScanResults({ addToast }) {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedVuln, setExpandedVuln] = useState(null);
  const wsRef = useRef(null);

  const handleCancelScan = async () => {
    try {
      const res = await fetch(`/api/v1/scan/${scanId}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        addToast('Scan cancellation request sent', 'info');
        setScan(prev => prev ? { ...prev, status: 'cancelled' } : null);
      } else {
        addToast('Failed to cancel scan', 'error');
      }
    } catch (e) {
      addToast('Offline mode: Cancelled scan simulation.', 'info');
      setScan(prev => prev ? { ...prev, status: 'cancelled' } : null);
    }
  };

  const handleToggleFalsePositive = async (vulnId) => {
    try {
      const res = await fetch(`/api/v1/vulnerability/${vulnId}/false-positive`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setScan(prev => {
          if (!prev) return null;
          const updatedVulns = prev.vulnerabilities.map(v => 
            v.id === vulnId ? { ...v, false_positive: data.false_positive } : v
          );
          return { ...prev, vulnerabilities: updatedVulns };
        });
        addToast(`Marked vulnerability #${vulnId} as ${data.false_positive ? 'False Positive' : 'Valid'}`, 'success');
      } else {
        addToast('Failed to toggle false positive status', 'error');
      }
    } catch (e) {
      setScan(prev => {
        if (!prev) return null;
        const updatedVulns = prev.vulnerabilities.map(v => {
          if (v.id === vulnId) {
            const newFp = !v.false_positive;
            addToast(`Offline mode: Marked vulnerability #${vulnId} as ${newFp ? 'False Positive' : 'Valid'}`, 'info');
            return { ...v, false_positive: newFp };
          }
          return v;
        });
        return { ...prev, vulnerabilities: updatedVulns };
      });
    }
  };

  useEffect(() => {
    let timer = null;
    let isMounted = true;

    async function fetchInitial() {
      try {
        const res = await fetch(`/api/v1/scan/${scanId}/status`);
        if (res.ok) {
          const data = await res.json();
          if (isMounted) setScan(data);
        } else {
          if (scanId.startsWith('scan_')) {
            startSimulation();
          }
        }
      } catch (err) {
        if (scanId.startsWith('scan_')) {
          startSimulation();
        } else {
          addToast('Could not load scan status', 'error');
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    function startSimulation() {
      setScan({
        scan_id: scanId,
        target: 'http://testphp.vulnweb.com',
        status: 'running',
        current_module: 'discovery',
        duration: 0,
        summary: {
          pages_discovered: 5,
          pages_scanned: 0,
          vulnerabilities_found: 0,
          severity_distribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        },
        vulnerabilities: [],
        modules_used: ['injection', 'xss', 'auth', 'config', 'api', 'privilege', 'session'],
        ai_analysis_enabled: true
      });

      let step = 0;
      timer = setInterval(() => {
        setScan((prev) => {
          if (!prev) return null;
          if (prev.status === 'cancelled') {
            clearInterval(timer);
            return prev;
          }
          step += 1;
          
          let newStatus = prev.status;
          let newVulns = [...prev.vulnerabilities];
          let discovered = prev.summary.pages_discovered;
          let scanned = prev.summary.pages_scanned;
          
          let currentModule = 'discovery';
          if (step > 2 && step <= 5) currentModule = 'xss';
          else if (step > 5 && step <= 8) currentModule = 'injection';
          else if (step > 8 && step <= 11) currentModule = 'ai_analysis';
          else if (step > 11 && step <= 13) currentModule = 'exploitation';
          else if (step > 13) {
            currentModule = '';
            newStatus = 'completed';
          }
          
          if (step === 3) {
            discovered = 15;
            scanned = 5;
            addToast('Discovery phase completed. Starting module scans...', 'info');
          } else if (step === 6) {
            scanned = 15;
            newVulns.push({
              id: 1,
              type: 'xss',
              subtype: 'reflected',
              severity: 'high',
              url: 'http://testphp.vulnweb.com/search.php',
              parameter: 'query',
              payload: "<script>alert('XSS')</script>",
              description: "Reflected XSS vulnerability in parameter 'query'",
              remediation: "Implement proper output encoding based on context. Use Content Security Policy (CSP).",
              ai_remediation: "1. Escape output in HTML context using htmlspecialchars() or a templating engine.\n2. Add a strong Content Security Policy header: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-randomvalue';\n3. Specifically sanitize the 'query' parameter.",
              confidence: 0.85,
              risk_score: 8.2,
              exploit_complexity: 'Easy - Can be exploited with basic tools',
              exploitation_confirmed: true,
              exploitation_proof: 'Benign payload reflected directly in page body: <script>console.log(\'XSS_CONFIRMED\')</script>',
              false_positive: false
            });
            addToast('Reflected XSS vulnerability found!', 'warning');
          } else if (step === 10) {
            newVulns.push({
              id: 2,
              type: 'sql_injection',
              subtype: 'error_based',
              severity: 'critical',
              url: 'http://testphp.vulnweb.com/listproducts.php',
              parameter: 'cat',
              payload: "1' OR 1=1--",
              description: "SQL Injection vulnerability detected in parameter 'cat'",
              remediation: "Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
              ai_remediation: "1. Parameterize all queries using PDO in PHP.\n2. Ensure least-privilege db access.\n3. Add input validation rules.",
              confidence: 0.95,
              risk_score: 9.8,
              exploit_complexity: 'Hard - Requires specialized tools and knowledge',
              exploitation_confirmed: true,
              exploitation_proof: 'Database confirmed via SQLi:\nType: MySQL\nVersion: 5.7.34-log\nSafe union-based query proof returned.',
              false_positive: false
            });
            addToast('CRITICAL: SQL Injection vulnerability found!', 'error');
          }
          
          if (newStatus === 'completed') {
            addToast('Scan finished successfully!', 'success');
            clearInterval(timer);
          }

          const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
          newVulns.forEach((v) => { counts[v.severity] += 1; });

          return {
            ...prev,
            status: newStatus,
            current_module: currentModule,
            duration: step * 2,
            summary: {
              pages_discovered: discovered,
              pages_scanned: scanned,
              vulnerabilities_found: newVulns.length,
              severity_distribution: counts
            },
            vulnerabilities: newVulns
          };
        });
      }, 2000);
    }

    if (!scanId.startsWith('scan_')) {
      fetchInitial();
      
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;
      
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (isMounted) {
            setScan(data);
            if (data.status === 'completed' || data.status === 'failed') {
              ws.close();
            }
          }
        } catch (e) {
          console.error(e);
        }
      };

      ws.onerror = () => {
        timer = setInterval(async () => {
          try {
            const res = await fetch(`/api/v1/scan/${scanId}/status`);
            if (res.ok && isMounted) {
              const data = await res.json();
              setScan(data);
              if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
                clearInterval(timer);
              }
            }
          } catch (e) {
            console.error('Polling error:', e);
          }
        }, 3000);
      };
    } else {
      fetchInitial();
    }

    return () => {
      isMounted = false;
      if (timer) clearInterval(timer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [scanId]);

  const toggleExpand = (id) => {
    setExpandedVuln(expandedVuln === id ? null : id);
  };

  if (loading) return <div className="spinner"></div>;
  if (!scan) {
    return (
      <div>
        <Link to="/" className="btn btn-secondary" style={{ marginBottom: '2rem' }}>
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div className="card text-center">
          <h3>Scan Report Not Found</h3>
          <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
            The scan ID {scanId} does not exist or has been deleted.
          </p>
        </div>
      </div>
    );
  }

  const { status, target, duration, summary, vulnerabilities } = scan;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem' }}>
        <Link to="/" className="btn btn-secondary">
          <ArrowLeft size={16} /> Dashboard
        </Link>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {(status === 'running' || status === 'pending') && (
            <button className="btn btn-danger" onClick={handleCancelScan} style={{ padding: '0.45rem 1rem', fontSize: '0.8rem' }}>
              <Ban size={14} /> Cancel Scan
            </button>
          )}
          {status === 'pending' && (
            <span className="status-pill status-pending">
              <span className="status-dot"></span>
              Scan Pending
            </span>
          )}
          {status === 'running' && (
            <span className="status-pill status-running">
              <span className="status-dot"></span>
              Scan In Progress
            </span>
          )}
          {status === 'completed' && (
            <span className="status-pill status-completed">
              <span className="status-dot"></span>
              Scan Completed
            </span>
          )}
          {status === 'failed' && (
            <span className="status-pill status-failed">
              <span className="status-dot"></span>
              Scan Failed
            </span>
          )}
          {status === 'cancelled' && (
            <span className="status-pill status-failed" style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', color: 'var(--color-critical)', borderColor: 'rgba(239, 68, 68, 0.2)' }}>
              <span className="status-dot" style={{ backgroundColor: 'var(--color-critical)' }}></span>
              Scan Cancelled
            </span>
          )}
        </div>
      </div>

      <div className="header-section">
        <span className="pill-badge">Scan Report</span>
        <h1 className="page-title" style={{ wordBreak: 'break-all', fontSize: '1.8rem' }}>{target}</h1>
        <p className="page-subtitle">Scan ID: {scanId} • Duration: {duration || 0} seconds</p>
      </div>

      {status === 'running' && scan.current_module && (
        <div className="card" style={{ marginBottom: '2rem', padding: '1rem', borderLeft: '4px solid var(--accent-primary)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="spinner-small" style={{ width: '16px', height: '16px', borderWidth: '2px' }}></div>
            <span>
              Active Phase: <strong style={{ color: 'var(--accent-primary)', textTransform: 'uppercase', fontSize: '0.85rem', letterSpacing: '0.5px' }}>{scan.current_module}</strong>
            </span>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Orchestrating security payloads and analyzers...
          </span>
        </div>
      )}

      {/* Stats counters */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <div className="card stat-card">
          <div className="stat-info">
            <h4>Pages Found</h4>
            <div className="stat-value">{summary.pages_discovered}</div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-info">
            <h4>Pages Scanned</h4>
            <div className="stat-value">{summary.pages_scanned}</div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-info">
            <h4>Total Vulnerabilities</h4>
            <div className="stat-value" style={{ color: summary.vulnerabilities_found > 0 ? 'var(--color-high)' : 'var(--text-primary)' }}>
              {summary.vulnerabilities_found}
            </div>
          </div>
        </div>
        <div className="card stat-card">
          <div className="stat-info">
            <h4>Security Grade</h4>
            <div className="stat-value" style={{ color: summary.severity_distribution.critical > 0 ? 'var(--color-critical)' : summary.severity_distribution.high > 0 ? 'var(--color-high)' : 'var(--color-success)' }}>
              {summary.severity_distribution.critical > 0 ? 'F' : summary.severity_distribution.high > 0 ? 'D' : summary.severity_distribution.medium > 0 ? 'C' : 'A'}
            </div>
          </div>
        </div>
      </div>

      {/* Severity distributions header */}
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '2rem' }}>
        {Object.entries(summary.severity_distribution).map(([sev, count]) => (
          <div
            key={sev}
            className="card"
            style={{
              flex: '1 1 120px',
              padding: '1rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              borderLeft: `4px solid var(--color-${sev})`
            }}
          >
            <span style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'capitalize', color: 'var(--text-secondary)' }}>{sev}</span>
            <span style={{ fontSize: '1.25rem', fontWeight: 700, color: `var(--color-${sev})` }}>{count}</span>
          </div>
        ))}
      </div>

      {/* Findings details */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            <ShieldAlert size={18} />
            Detected Vulnerabilities ({vulnerabilities.length})
          </h3>
        </div>

        {vulnerabilities.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem 0' }}>
            <CheckCircle size={48} style={{ color: 'var(--color-success)', marginBottom: '1rem' }} />
            <h4>No Vulnerabilities Detected</h4>
            <p style={{ color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
              Awesome! No security vulnerabilities were found on the endpoints analyzed.
            </p>
          </div>
        ) : (
          <div className="vulns-list">
            {vulnerabilities.map((vuln) => (
              <div key={vuln.id} className="vuln-item" style={{ borderLeft: `4px solid var(--color-${vuln.severity})`, opacity: vuln.false_positive ? 0.6 : 1, backgroundColor: vuln.false_positive ? 'rgba(255, 255, 255, 0.01)' : 'transparent' }}>
                <div className="vuln-header" onClick={() => toggleExpand(vuln.id)}>
                  <div className="vuln-summary">
                    <span className={`vuln-badge ${vuln.severity}`}>{vuln.severity}</span>
                    {vuln.false_positive && (
                      <span className="vuln-badge" style={{ backgroundColor: 'rgba(255, 255, 255, 0.06)', color: 'var(--text-muted)', border: '1px solid var(--border-color)' }}>
                        False Positive
                      </span>
                    )}
                    {vuln.exploitation_confirmed && (
                      <span className="vuln-badge" style={{ backgroundColor: 'rgba(0, 242, 254, 0.1)', color: 'var(--accent-primary)', border: '1px solid rgba(0, 242, 254, 0.2)' }}>
                        Exploited
                      </span>
                    )}
                    <span style={{ fontWeight: 600, fontSize: '0.95rem', textDecoration: vuln.false_positive ? 'line-through' : 'none', color: vuln.false_positive ? 'var(--text-muted)' : 'var(--text-primary)' }}>{vuln.description}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      Risk Score: <strong style={{ color: 'var(--text-primary)' }}>{vuln.risk_score || 'N/A'}</strong>
                    </span>
                    {expandedVuln === vuln.id ? <ChevronDown size={16} /> : <ChevronDown size={16} style={{ transform: 'rotate(-90deg)' }} />}
                  </div>
                </div>

                {expandedVuln === vuln.id && (
                  <div className="vuln-details">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
                      {/* AI Confidence */}
                      {vuln.confidence !== undefined && (
                        <div className="detail-section" style={{ margin: 0 }}>
                          <h5>AI Confidence</h5>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.5rem' }}>
                            <div style={{ flex: 1, height: '8px', backgroundColor: 'rgba(255, 255, 255, 0.04)', borderRadius: '4px', overflow: 'hidden' }}>
                              <div style={{ width: `${vuln.confidence * 100}%`, height: '100%', background: 'var(--accent-gradient)' }} />
                            </div>
                            <span style={{ fontWeight: 700, color: 'var(--accent-primary)' }}>
                              {Math.round(vuln.confidence * 100)}%
                            </span>
                          </div>
                        </div>
                      )}

                      {/* Exploit Complexity */}
                      {vuln.exploit_complexity && (
                        <div className="detail-section" style={{ margin: 0 }}>
                          <h5>Exploit Complexity</h5>
                          <div style={{ marginTop: '0.5rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {vuln.exploit_complexity}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Safe Exploitation Proof */}
                    {vuln.exploitation_confirmed && vuln.exploitation_proof && (
                      <div className="detail-section" style={{ border: '1px solid rgba(0, 242, 254, 0.2)', padding: '1rem', borderRadius: '8px', backgroundColor: 'rgba(0, 242, 254, 0.02)', marginBottom: '1.5rem' }}>
                        <h5 style={{ color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
                          <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--accent-primary)', boxShadow: '0 0 8px var(--accent-primary)' }} />
                          Safe Exploitation Confirmed (Benign PoC)
                        </h5>
                        <pre className="code-box" style={{ marginTop: '0.75rem', border: '1px dashed rgba(0, 242, 254, 0.15)', backgroundColor: 'rgba(0, 0, 0, 0.25)', fontSize: '0.85rem' }}>
                          {vuln.exploitation_proof}
                        </pre>
                      </div>
                    )}

                    <div className="detail-section">
                      <h5>Vulnerable URL</h5>
                      <div className="code-box">{vuln.url}</div>
                    </div>

                    {vuln.parameter && (
                      <div className="detail-section">
                        <h5>Parameter</h5>
                        <div style={{ fontSize: '0.9rem', fontFamily: 'monospace', color: 'var(--accent-primary)' }}>
                          {vuln.parameter}
                        </div>
                      </div>
                    )}

                    {vuln.payload && (
                      <div className="detail-section">
                        <h5>Tested Payload</h5>
                        <div className="code-box">{vuln.payload}</div>
                      </div>
                    )}

                    <div className="detail-section">
                      <h5>Standard Remediation</h5>
                      <div className="remediation-box">{vuln.remediation}</div>
                    </div>

                    {vuln.ai_remediation && (
                      <div className="detail-section">
                        <h5>AI-Powered Specific Advice</h5>
                        <div className="ai-box" style={{ whiteSpace: 'pre-wrap' }}>
                          {vuln.ai_remediation}
                        </div>
                      </div>
                    )}

                    {/* False Positive Actions Footer */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)' }}>
                      <button
                        className={`btn ${vuln.false_positive ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleToggleFalsePositive(vuln.id);
                        }}
                        style={{ padding: '0.4rem 1rem', fontSize: '0.8rem' }}
                      >
                        <AlertCircle size={14} />
                        {vuln.false_positive ? 'Mark as Valid Finding' : 'Mark as False Positive'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default ScanResults;
