import React, { useState, useEffect } from 'react';
import { ShieldAlert, Search, ChevronDown, AlertCircle } from 'lucide-react';

function Vulnerabilities({ addToast }) {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedVuln, setExpandedVuln] = useState(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('valid'); // Default to valid findings only

  useEffect(() => {
    async function fetchVulns() {
      try {
        const res = await fetch('/api/v1/vulnerabilities');
        if (res.ok) {
          const data = await res.json();
          setVulns(data.vulnerabilities || []);
        } else {
          setMockData();
        }
      } catch (err) {
        console.error(err);
        setMockData();
      } finally {
        setLoading(false);
      }
    }

    function setMockData() {
      setVulns([
        {
          id: 1,
          type: 'xss',
          severity: 'high',
          url: 'http://testphp.vulnweb.com/search.php',
          parameter: 'query',
          payload: "<script>alert('XSS')</script>",
          description: "Reflected XSS vulnerability in parameter 'query'",
          remediation: "Implement proper output encoding based on context. Use Content Security Policy (CSP).",
          ai_remediation: "1. Escape output in HTML context using htmlspecialchars() or a templating engine.\n2. Add a strong Content Security Policy header: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-randomvalue';\n3. Specifically sanitize the 'query' parameter.",
          risk_score: 8.2,
          confidence: 0.85,
          exploit_complexity: 'Easy - Can be exploited with basic tools',
          exploitation_confirmed: true,
          exploitation_proof: 'Benign payload reflected directly in page body: <script>console.log(\'XSS_CONFIRMED\')</script>',
          false_positive: false
        },
        {
          id: 2,
          type: 'sql_injection',
          severity: 'critical',
          url: 'http://testphp.vulnweb.com/listproducts.php',
          parameter: 'cat',
          payload: "1' OR 1=1--",
          description: "SQL Injection vulnerability detected in parameter 'cat'",
          remediation: "Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
          ai_remediation: "1. Parameterize all queries using PDO in PHP.\n2. Ensure least-privilege db access.\n3. Add input validation rules.",
          risk_score: 9.8,
          confidence: 0.95,
          exploit_complexity: 'Hard - Requires specialized tools and knowledge',
          exploitation_confirmed: true,
          exploitation_proof: 'Database confirmed via SQLi:\nType: MySQL\nVersion: 5.7.34-log\nSafe union-based query proof returned.',
          false_positive: false
        },
        {
          id: 3,
          type: 'missing_security_headers',
          severity: 'medium',
          url: 'http://testphp.vulnweb.com/',
          parameter: 'Strict-Transport-Security',
          payload: null,
          description: "Missing 3 security headers: HSTS, CSP, X-Frame-Options",
          remediation: "Implement comprehensive security headers including CSP, HSTS, and X-Frame-Options.",
          ai_remediation: "Configure response headers in web server (Nginx/Apache) or application config:\n- Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n- X-Frame-Options: DENY\n- Content-Security-Policy: default-src 'self';",
          risk_score: 5.5,
          confidence: 0.99,
          exploit_complexity: 'Easy - Can be exploited with basic tools',
          exploitation_confirmed: false,
          false_positive: false
        }
      ]);
    }

    fetchVulns();
  }, []);

  const handleToggleFalsePositive = async (vulnId) => {
    try {
      const res = await fetch(`/api/v1/vulnerability/${vulnId}/false-positive`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setVulns(prev => 
          prev.map(v => v.id === vulnId ? { ...v, false_positive: data.false_positive } : v)
        );
        addToast(`Marked vulnerability #${vulnId} as ${data.false_positive ? 'False Positive' : 'Valid'}`, 'success');
      } else {
        addToast('Failed to toggle false positive status', 'error');
      }
    } catch (e) {
      setVulns(prev => 
        prev.map(v => {
          if (v.id === vulnId) {
            const newFp = !v.false_positive;
            addToast(`Offline mode: Marked vulnerability #${vulnId} as ${newFp ? 'False Positive' : 'Valid'}`, 'info');
            return { ...v, false_positive: newFp };
          }
          return v;
        })
      );
    }
  };

  const toggleExpand = (id) => {
    setExpandedVuln(expandedVuln === id ? null : id);
  };

  const filteredVulns = vulns.filter((v) => {
    const matchesSearch = 
      v.url.toLowerCase().includes(searchTerm.toLowerCase()) || 
      v.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (v.parameter && v.parameter.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesSeverity = severityFilter ? v.severity === severityFilter : true;
    const matchesType = typeFilter ? v.type === typeFilter : true;
    const matchesStatus = statusFilter === 'fp' 
      ? v.false_positive 
      : statusFilter === 'valid' 
        ? !v.false_positive 
        : true;

    return matchesSearch && matchesSeverity && matchesType && matchesStatus;
  });

  const uniqueTypes = [...new Set(vulns.map((v) => v.type))];

  return (
    <div>
      <div className="header-section">
        <span className="pill-badge">Vulnerabilities</span>
        <h1 className="page-title">Vulnerability Center</h1>
        <p className="page-subtitle">Inspect, filter, and remediate all security findings discovered across your targets.</p>
      </div>

      {/* Search and Filters Bar */}
      <div className="search-bar">
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            className="form-input search-input"
            style={{ paddingLeft: '2.5rem' }}
            placeholder="Search by URL, parameter, or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <select
          className="form-select filter-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <select
          className="form-select filter-select"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value="">All Types</option>
          {uniqueTypes.map((type) => (
            <option key={type} value={type}>
              {type.replace('_', ' ').replace('-', ' ')}
            </option>
          ))}
        </select>

        <select
          className="form-select filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Findings</option>
          <option value="valid">Valid Findings Only</option>
          <option value="fp">False Positives Only</option>
        </select>
      </div>

      {loading ? (
        <div className="spinner"></div>
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <ShieldAlert size={18} />
              Vulnerabilities ({filteredVulns.length})
            </h3>
          </div>

          {filteredVulns.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text-secondary)' }}>
              No vulnerabilities match the selected criteria.
            </div>
          ) : (
            <div className="vulns-list">
              {filteredVulns.map((vuln) => (
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
      )}
    </div>
  );
}

export default Vulnerabilities;
