import React, { useEffect, useRef } from 'react';
import { Terminal as TerminalIcon, Trash2 } from 'lucide-react';

export default function ProgressPanel({
  stats,
  sourceYields = {},
  logs = [],
  onClearLogs = () => {}
}) {
  const terminalEndRef = useRef(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Combined sources list for the progress pills
  const allYieldSourceIds = Object.keys(sourceYields);

  return (
    <div className="cyber-panel">
      <div className="section-header">
        <div className="section-title">
          <span>PROQRES VƏ TELEMETRİYA</span>
        </div>
      </div>

      {/* 4 Əsas Metrika Kartı */}
      <div className="metrics-row">
        {/* FAZA */}
        <div className={`metric-card ${stats.phase !== 'READY' && stats.phase !== 'DONE' ? 'active-card' : ''}`}>
          <div className="metric-label">FAZA</div>
          <div className="metric-val status-val glow-text">
            {stats.phase}
          </div>
        </div>

        {/* TAPILAN */}
        <div className="metric-card">
          <div className="metric-label">TAPILAN</div>
          <div className="metric-val">
            {stats.found.toLocaleString()}
          </div>
          <div className="metric-sub">
            ▲ {stats.filtered} sub filtr olundu → {(stats.found > stats.filtered ? stats.found - stats.filtered : stats.found).toLocaleString()} probe olunacaq
          </div>
        </div>

        {/* YOXLANILAN */}
        <div className="metric-card">
          <div className="metric-label">YOXLANILAN</div>
          <div className="metric-val">
            {stats.checked.toLocaleString()} / {(stats.found > stats.filtered ? stats.found - stats.filtered : stats.found).toLocaleString()}
          </div>
        </div>

        {/* CANLI */}
        <div className="metric-card">
          <div className="metric-label">CANLI</div>
          <div className="metric-val glow-text">
            {stats.live.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Nəticə verən mənbələrin pill-ləri */}
      {allYieldSourceIds.length > 0 && (
        <div className="pills-grid" style={{ maxHeight: '110px', overflowY: 'auto', padding: '4px 0' }}>
          {allYieldSourceIds.map(srcId => (
            <div key={srcId} className="source-pill active has-yield" style={{ fontSize: '11px', padding: '2px 8px' }}>
              <span className="pill-dot dot-green" />
              <span>{srcId}</span>
              <span className="pill-count">+{sourceYields[srcId].toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}

      {/* Canlı Terminal */}
      <div className="terminal-window">
        <div className="terminal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <TerminalIcon size={14} color="#00ff66" />
            <span className="terminal-title">TERMİNAL</span>
          </div>
          <button
            type="button"
            className="cyber-btn btn-outline"
            style={{ padding: '2px 6px', fontSize: '10px' }}
            onClick={onClearLogs}
            title="Logları təmizlə"
          >
            <Trash2 size={11} />
            TƏMİZLƏ
          </button>
        </div>

        <div className="terminal-body">
          {logs.length === 0 ? (
            <div style={{ color: '#274c30', fontStyle: 'italic' }}>
              [Sistem hazırdır. Skanlamaq üçün yuxarıdakı "BAŞLAT" düyməsinə klikləyin.]
            </div>
          ) : (
            logs.map((log, index) => (
              <div key={index} className="terminal-line">
                <span className="terminal-time">[{log.timestamp}]</span>
                <span className={`terminal-msg ${log.type || 'info'}`}>
                  {log.message}
                </span>
              </div>
            ))
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}
