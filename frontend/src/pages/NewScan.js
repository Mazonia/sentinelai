import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PlayCircle } from 'lucide-react';

function NewScan({ addToast }) {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState('');
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPages, setMaxPages] = useState(100);
  const [concurrency, setConcurrency] = useState(10);
  const [intensity, setIntensity] = useState('medium');
  const [aiAnalysis, setAiAnalysis] = useState(true);
  const [modules, setModules] = useState({
    injection: true,
    xss: true,
    auth: true,
    config: true,
    api: true,
    privilege: true,
    session: true
  });
  const [submitting, setSubmitting] = useState(false);

  const handleModuleChange = (module) => {
    setModules((prev) => ({ ...prev, [module]: !prev[module] }));
  };

  const getModuleLabel = (mod) => {
    const labels = {
      injection: 'Injection (SQL/Cmd)',
      xss: 'XSS (Reflected/Stored)',
      auth: 'Auth & Access Bypass',
      config: 'Security Configs/Headers',
      api: 'API Endpoint Scan',
      privilege: 'Privilege Escalation',
      session: 'Session Hijacking'
    };
    return labels[mod] || mod;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      addToast('Target URL must start with http:// or https://', 'error');
      return;
    }

    setSubmitting(true);
    const selectedModules = Object.keys(modules).filter((k) => modules[k]);

    if (selectedModules.length === 0) {
      addToast('Please select at least one scanning module', 'error');
      setSubmitting(false);
      return;
    }

    try {
      const res = await fetch('/api/v1/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          target_url: targetUrl,
          max_depth: parseInt(maxDepth),
          max_pages: parseInt(maxPages),
          concurrency: parseInt(concurrency),
          modules: selectedModules,
          ai_analysis: aiAnalysis,
          payload_intensity: intensity
        })
      });

      if (res.ok) {
        const data = await res.json();
        addToast('Scan launched successfully!', 'success');
        navigate(`/scan/${data.scan_id}`);
      } else {
        const errorData = await res.json().catch(() => ({}));
        addToast(errorData.detail || 'Failed to start scan', 'error');
      }
    } catch (err) {
      console.error(err);
      addToast('Backend unreachable, simulated scan started.', 'info');
      // Simulated scan id fallback for demo purposes
      const fakeScanId = `scan_${Date.now().toString().slice(-6)}`;
      navigate(`/scan/${fakeScanId}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <div className="header-section">
        <span className="pill-badge">Configure</span>
        <h1 className="page-title">Start Security Scan</h1>
        <p className="page-subtitle">Launch a comprehensive vulnerability scan using advanced heuristics and AI analysis.</p>
      </div>

      <div className="card" style={{ maxWidth: '800px', margin: '0 auto' }}>
        <form onSubmit={handleSubmit}>
          {/* Target URL */}
          <div className="form-group">
            <label className="form-label">Target URL</label>
            <input
              type="text"
              className="form-input"
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {/* Crawl Depth */}
            <div className="form-group">
              <label className="form-label">Crawl Depth (Max Depth)</label>
              <div className="range-slider">
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(e.target.value)}
                />
                <span className="range-value">{maxDepth}</span>
              </div>
            </div>

            {/* Max Pages */}
            <div className="form-group">
              <label className="form-label">Max Pages to Crawl</label>
              <div className="range-slider">
                <input
                  type="range"
                  min="10"
                  max="1000"
                  step="10"
                  value={maxPages}
                  onChange={(e) => setMaxPages(e.target.value)}
                />
                <span className="range-value">{maxPages}</span>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {/* Concurrency */}
            <div className="form-group">
              <label className="form-label">Max Concurrency</label>
              <div className="range-slider">
                <input
                  type="range"
                  min="1"
                  max="50"
                  value={concurrency}
                  onChange={(e) => setConcurrency(e.target.value)}
                />
                <span className="range-value">{concurrency}</span>
              </div>
            </div>

            {/* Payload Intensity */}
            <div className="form-group">
              <label className="form-label">Payload Intensity</label>
              <select
                className="form-select"
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
              >
                <option value="low">Low (Fast, less intrusive)</option>
                <option value="medium">Medium (Balanced testing)</option>
                <option value="high">High (Deep fuzzing, noisy)</option>
              </select>
            </div>
          </div>

          {/* Modules Selection */}
          <div className="form-group" style={{ marginTop: '0.5rem' }}>
            <label className="form-label">Vulnerability Modules</label>
            <div className="checkbox-grid">
              {Object.keys(modules).map((mod) => (
                <label key={mod} className="checkbox-card">
                  <input
                    type="checkbox"
                    checked={modules[mod]}
                    onChange={() => handleModuleChange(mod)}
                  />
                  <span>{getModuleLabel(mod)}</span>
                </label>
              ))}
            </div>
          </div>

          {/* AI Analysis Toggle */}
          <div className="form-group switch-container" style={{ marginTop: '1.5rem' }}>
            <div>
              <span className="form-label" style={{ marginBottom: '0.2rem' }}>AI False Positive Reduction & Remediation</span>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Uses AI to grade finding confidence and generate custom mitigation advice.
              </p>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={aiAnalysis}
                onChange={(e) => setAiAnalysis(e.target.checked)}
              />
              <span className="slider"></span>
            </label>
          </div>

          {/* Submit */}
          <div style={{ marginTop: '2rem', display: 'flex', justifyContent: 'flex-end' }}>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <PlayCircle size={18} />
              {submitting ? 'Launching Scan...' : 'Launch Security Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewScan;
