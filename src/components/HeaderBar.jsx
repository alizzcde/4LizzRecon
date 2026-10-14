import React from 'react';
import { Terminal, Play, Square, Shield, Wifi, WifiOff, Key } from 'lucide-react';

export default function HeaderBar({
  target,
  setTarget,
  isRunning,
  onStart,
  onStop,
  connected,
  onOpenKeysModal
}) {
  return (
    <header className="cyber-nav glow-box">
      <div className="brand-section">
        <div className="brand-logo">
          <Terminal size={18} color="#00ff66" />
        </div>
        <div>
          <div className="brand-title glow-text">4Lizz Recon // APEX ENGINE</div>
          <div className="brand-subtitle">
            REAL-TIME OSINT • ASYNC DNS RESOLVER • HTTP PROBER
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
        {/* Backend Status */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 8px',
            borderRadius: '3px',
            background: connected ? 'rgba(0, 255, 102, 0.08)' : 'rgba(255, 51, 68, 0.08)',
            border: `1px solid ${connected ? '#164320' : '#4d1418'}`,
            fontSize: '11px',
            color: connected ? '#00ff66' : '#ff4455'
          }}
          title={connected ? "FastAPI Recon Engine aktivdir" : "Backend əlaqəsi gözlənilir (localhost:8000)"}
        >
          {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
          <span>{connected ? "ENGINE: ONLINE" : "CONNECTING..."}</span>
        </div>

        {/* API Keys Button */}
        <button
          type="button"
          className="cyber-btn btn-outline"
          onClick={onOpenKeysModal}
          style={{
            borderColor: '#225d30',
            color: '#00ff66',
            background: 'rgba(0, 255, 102, 0.06)'
          }}
          title="Shodan, SecurityTrails, ZoomEye, VirusTotal API key-lərini tənzimlə"
        >
          <Key size={13} />
          API KEYS
        </button>

        {/* Target input */}
        <div className="target-bar">
          <Shield size={16} color="#00ff66" />
          <input
            type="text"
            className="target-input"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="hədəf domen (məs. tesla.com)"
            disabled={isRunning}
          />
        </div>

        {/* Action Button */}
        {!isRunning ? (
          <button
            type="button"
            className="cyber-btn"
            onClick={onStart}
            disabled={!target.trim() || !connected}
            style={{ opacity: !target.trim() || !connected ? 0.6 : 1 }}
          >
            <Play size={14} fill="#00ff66" />
            BAŞLAT
          </button>
        ) : (
          <button type="button" className="cyber-btn btn-stop" onClick={onStop}>
            <Square size={14} fill="#ff3344" />
            DAYANDIR
          </button>
        )}
      </div>
    </header>
  );
}
