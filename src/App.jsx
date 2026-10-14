import React, { useState, useEffect, useRef } from 'react';
import HeaderBar from './components/HeaderBar';
import ModulesConfig from './components/ModulesConfig';
import ProgressPanel from './components/ProgressPanel';
import ResultsPanel from './components/ResultsPanel';
import ApiKeysModal from './components/ApiKeysModal';
import { PASSIVE_SOURCES, EXTERNAL_TOOLS, ACTIVE_TECHNIQUES } from './data/sourcesData';

export default function App() {
  const [target, setTarget] = useState('tesla.com');
  const [isRunning, setIsRunning] = useState(false);
  const [connected, setConnected] = useState(false);
  const [isKeysModalOpen, setIsKeysModalOpen] = useState(false);

  // Modul Tənzimləmə Vəziyyəti
  const [passiveSources, setPassiveSources] = useState(PASSIVE_SOURCES);
  const [externalTools, setExternalTools] = useState(EXTERNAL_TOOLS);
  const [activeTechniques, setActiveTechniques] = useState(ACTIVE_TECHNIQUES);
  const [options, setOptions] = useState({
    httpProbing: true,
    smartFilter: true,
    altPortScan: false,
    deadPoolProbe: false,
    maxScope: false
  });

  // Canlı Skanlama Telemetriyası
  const [stats, setStats] = useState({
    phase: 'HAZIR',
    found: 0,
    checked: 0,
    live: 0,
    filtered: 0
  });

  const [sourceYields, setSourceYields] = useState({});
  const [logs, setLogs] = useState([]);
  const [subdomains, setSubdomains] = useState([]);

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  // Quraşdırılmış CLI alətlərini və aktiv API açarlarını backend-dən əldə et
  const refreshConfigAndTools = () => {
    // 1. CLI alətləri
    fetch('http://127.0.0.1:8000/api/tools')
      .then(res => res.json())
      .then(toolsMap => {
        setExternalTools(prev =>
          prev.map(tool => ({
            ...tool,
            installed: !!toolsMap[tool.id],
            active: !!toolsMap[tool.id]
          }))
        );
      })
      .catch(() => {});

    // 2. API açarları konfiqurasiya vəziyyəti
    fetch('http://127.0.0.1:8000/api/config')
      .then(res => res.json())
      .then(data => {
        const activeMap = data.active_status || {};
        const keyMapToSource = {
          shodan_api_key: 'shodan',
          securitytrails_api_key: 'securitytrails',
          zoomeye_api_key: 'zoomeye',
          virustotal_api_key: 'virustotal',
          chaos_api_key: 'chaos',
          github_token: 'github_search'
        };

        setPassiveSources(prev =>
          prev.map(src => {
            for (const [keyField, srcId] of Object.entries(keyMapToSource)) {
              if (src.id === srcId) {
                const isKeyPresent = !!activeMap[keyField];
                return {
                  ...src,
                  hasKey: isKeyPresent,
                  active: isKeyPresent ? true : src.active
                };
              }
            }
            return src;
          })
        );
      })
      .catch(() => {});
  };

  useEffect(() => {
    refreshConfigAndTools();
  }, []);

  // WebSocket Əlaqəsi
  const connectWebSocket = () => {
    try {
      const ws = new WebSocket('ws://127.0.0.1:8000/ws/recon');
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        addLog('4Lizz Recon Mühərrikinə qoşuldu (WebSocket onlayn)', 'success');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          if (msg.type === 'log') {
            addLog(msg.message, msg.level, msg.timestamp);
          } else if (msg.type === 'stats') {
            setStats({
              phase: msg.phase,
              found: msg.found,
              checked: msg.checked,
              live: msg.live,
              filtered: msg.filtered
            });
          } else if (msg.type === 'source_yield') {
            setSourceYields(prev => ({
              ...prev,
              [msg.source]: (prev[msg.source] || 0) + msg.count
            }));
          } else if (msg.type === 'subdomain_found') {
            setSubdomains(prev => [msg.data, ...prev]);
          } else if (msg.type === 'done') {
            setIsRunning(false);
          }
        } catch {
          // Ignore JSON parse errors
        }
      };

      ws.onclose = () => {
        setConnected(false);
        setIsRunning(false);
        reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        setConnected(false);
      };
    } catch {
      setConnected(false);
      reconnectTimeoutRef.current = setTimeout(connectWebSocket, 3000);
    }
  };

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, []);

  const addLog = (message, type = 'info', timestamp = null) => {
    const timeStr = timestamp || new Date().toTimeString().split(' ')[0];
    setLogs(prev => [...prev, { timestamp: timeStr, message, type }]);
  };

  const handleStart = () => {
    if (!target.trim() || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      addLog('Xəta: Backend WebSocket bağlantısı qurula bilmədi!', 'wildcard');
      return;
    }

    // Telemetriyanı sıfırla
    setSubdomains([]);
    setSourceYields({});
    setLogs([]);
    setIsRunning(true);
    setStats({
      phase: 'BAŞLADILIR',
      found: 0,
      checked: 0,
      live: 0,
      filtered: 0
    });

    const activeSourceIds = passiveSources.filter(s => s.active).map(s => s.id);
    const activeToolIds = externalTools.filter(t => t.active).map(t => t.id);
    const activeTechniqueIds = activeTechniques.filter(t => t.active).map(t => t.id);

    // Başlatma əmrini backend-ə göndər
    wsRef.current.send(
      JSON.stringify({
        action: 'start',
        target: target.trim(),
        sources: activeSourceIds,
        tools: activeToolIds,
        activeTechniques: activeTechniqueIds,
        options: options
      })
    );
  };

  const handleStop = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'stop' }));
    }
    setIsRunning(false);
    addLog('Dayandırma əmri göndərildi...', 'wildcard');
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  return (
    <div className="app-container">
      {/* Üst Naviqasiya Paneli */}
      <HeaderBar
        target={target}
        setTarget={setTarget}
        isRunning={isRunning}
        onStart={handleStart}
        onStop={handleStop}
        connected={connected}
        onOpenKeysModal={() => setIsKeysModalOpen(true)}
      />

      {/* 1. Modullar və Mənbələr Paneli */}
      <ModulesConfig
        passiveSources={passiveSources}
        setPassiveSources={setPassiveSources}
        externalTools={externalTools}
        setExternalTools={setExternalTools}
        activeTechniques={activeTechniques}
        setActiveTechniques={setActiveTechniques}
        options={options}
        setOptions={setOptions}
        sourceYields={sourceYields}
      />

      {/* 2. İrəliləyiş və Canlı Terminal Paneli */}
      <ProgressPanel
        stats={stats}
        sourceYields={sourceYields}
        logs={logs}
        onClearLogs={handleClearLogs}
      />

      {/* 3. Nəticələr və İxrac Paneli */}
      <ResultsPanel
        subdomains={subdomains}
        totalLiveCount={stats.live}
      />

      {/* API Açarları Modalı */}
      <ApiKeysModal
        isOpen={isKeysModalOpen}
        onClose={() => setIsKeysModalOpen(false)}
        onKeysUpdated={refreshConfigAndTools}
      />
    </div>
  );
}
