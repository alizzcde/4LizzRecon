import React, { useState } from 'react';
import { Flame } from 'lucide-react';

export default function ModulesConfig({
  passiveSources,
  setPassiveSources,
  externalTools,
  setExternalTools,
  activeTechniques,
  setActiveTechniques,
  options,
  setOptions,
  sourceYields = {}
}) {
  const [passiveMaster, setPassiveMaster] = useState(true);
  const [externalMaster, setExternalMaster] = useState(true);
  const [techniquesMaster, setTechniquesMaster] = useState(true);

  // Toggle all passive
  const toggleAllPassive = () => {
    const nextState = !passiveMaster;
    setPassiveMaster(nextState);
    setPassiveSources(prev => prev.map(s => ({ ...s, active: nextState })));
  };

  // Toggle single passive pill
  const togglePassivePill = (id) => {
    setPassiveSources(prev =>
      prev.map(s => (s.id === id ? { ...s, active: !s.active } : s))
    );
  };

  // Toggle all external
  const toggleAllExternal = () => {
    const nextState = !externalMaster;
    setExternalMaster(nextState);
    setExternalTools(prev => prev.map(t => ({ ...t, active: nextState })));
  };

  // Toggle single external pill
  const toggleExternalPill = (id) => {
    setExternalTools(prev =>
      prev.map(t => (t.id === id ? { ...t, active: !t.active } : t))
    );
  };

  // Toggle all active techniques
  const toggleAllTechniques = () => {
    const nextState = !techniquesMaster;
    setTechniquesMaster(nextState);
    setActiveTechniques(prev => prev.map(t => ({ ...t, active: nextState })));
  };

  // Toggle single active technique pill
  const toggleTechniquePill = (id) => {
    setActiveTechniques(prev =>
      prev.map(t => (t.id === id ? { ...t, active: !t.active } : t))
    );
  };

  const handleMaxScopeToggle = () => {
    const nextVal = !options.maxScope;
    setOptions(prev => ({
      ...prev,
      maxScope: nextVal,
      altPortScan: nextVal ? true : prev.altPortScan,
      deadPoolProbe: nextVal ? true : prev.deadPoolProbe,
      smartFilter: nextVal ? false : prev.smartFilter
    }));
  };

  return (
    <div className="cyber-panel">
      {/* 1. PASSİV MƏNBƏLƏR */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div className="section-header">
          <div className="section-title-wrap" onClick={toggleAllPassive}>
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={passiveMaster}
              onChange={toggleAllPassive}
            />
            <div className="section-title">
              <span>PASSİV MƏNBƏLƏR</span>
              <span className="section-hint">kliklə: aç / bağla</span>
            </div>
          </div>
        </div>

        <div className="pills-grid">
          {passiveSources.map(source => {
            const hasYield = !!sourceYields[source.id];
            const yieldCount = sourceYields[source.id];

            return (
              <div
                key={source.id}
                className={`source-pill ${source.active ? 'active' : 'inactive'} ${hasYield ? 'has-yield' : ''}`}
                onClick={() => togglePassivePill(source.id)}
                title={source.hasKey ? `${source.name} (Aktiv)` : `${source.name} (API key tələb olunur)`}
              >
                <span
                  className={`pill-dot ${
                    source.active
                      ? source.hasKey ? 'dot-green' : 'dot-red'
                      : 'dot-dim'
                  }`}
                />
                <span>{source.name}</span>
                {hasYield && <span className="pill-count">+{yieldCount}</span>}
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. XARİCİ TOOL-LAR */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '6px' }}>
        <div className="section-header">
          <div className="section-title-wrap" onClick={toggleAllExternal}>
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={externalMaster}
              onChange={toggleAllExternal}
            />
            <div className="section-title">
              <span>XARİCİ TOOL-LAR</span>
              <span className="section-hint">sistemdə olmayanlar deaktivdir</span>
            </div>
          </div>
        </div>

        <div className="pills-grid">
          {externalTools.map(tool => {
            const hasYield = !!sourceYields[tool.id];
            const yieldCount = sourceYields[tool.id];

            return (
              <div
                key={tool.id}
                className={`source-pill ${tool.active ? 'active' : 'inactive'} ${hasYield ? 'has-yield' : ''}`}
                onClick={() => toggleExternalPill(tool.id)}
                title={tool.installed ? `${tool.name} (Mövcuddur)` : `${tool.name} (Sistemdə tapılmadı)`}
              >
                <span
                  className={`pill-dot ${
                    tool.active
                      ? tool.installed ? 'dot-green' : 'dot-red'
                      : 'dot-dim'
                  }`}
                />
                <span>{tool.name}</span>
                {hasYield && <span className="pill-count">+{yieldCount}</span>}
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. AKTİV TEXNİKALAR */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '6px' }}>
        <div className="section-header">
          <div className="section-title-wrap" onClick={toggleAllTechniques}>
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={techniquesMaster}
              onChange={toggleAllTechniques}
            />
            <div className="section-title">
              <span>AKTİV TEXNİKALAR</span>
              <span className="section-hint">fazan bağlamaq üçün seç</span>
            </div>
          </div>
        </div>

        <div className="pills-grid">
          {activeTechniques.map(tech => {
            const hasYield = !!sourceYields[tech.id];
            const yieldCount = sourceYields[tech.id];

            return (
              <div
                key={tech.id}
                className={`source-pill ${tech.active ? 'active' : 'inactive'} ${hasYield ? 'has-yield' : ''}`}
                onClick={() => toggleTechniquePill(tech.id)}
              >
                <span className={`pill-dot ${tech.active ? 'dot-green' : 'dot-dim'}`} />
                <span>{tech.name}</span>
                {hasYield && <span className="pill-count">+{yieldCount}</span>}
              </div>
            );
          })}
        </div>

        {/* Seçimlər Checkboxları */}
        <div className="techniques-options-grid" style={{ marginTop: '10px' }}>
          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={options.httpProbing}
              onChange={(e) => setOptions(prev => ({ ...prev, httpProbing: e.target.checked }))}
            />
            <span>HTTP Probing (canlı yoxlama)</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={options.smartFilter}
              onChange={(e) => setOptions(prev => ({ ...prev, smartFilter: e.target.checked }))}
            />
            <span style={{ color: '#5b8c66' }}>Smart Filter (infrastruktur sub-larını qruplaşdır, təkrarı azalt)</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={options.altPortScan}
              onChange={(e) => setOptions(prev => ({ ...prev, altPortScan: e.target.checked }))}
            />
            <span style={{ color: '#5b8c66' }}>Port Scan (8880/8443/8000/3000/5000... canlı hostlarda)</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={options.deadPoolProbe}
              onChange={(e) => setOptions(prev => ({ ...prev, deadPoolProbe: e.target.checked }))}
            />
            <span style={{ color: '#5b8c66' }}>Dead Pool Probe (DNS-də resolve olmayanları da HTTP ilə yoxla)</span>
          </label>

          {/* MAX SCOPE MODE */}
          <div className="scope-warning-box">
            <label className="cyber-checkbox-label" style={{ color: '#ff9944', fontWeight: 600 }}>
              <input
                type="checkbox"
                className="cyber-checkbox"
                style={{ borderColor: '#ff9944' }}
                checked={options.maxScope}
                onChange={handleMaxScopeToggle}
              />
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <Flame size={14} color="#ff8800" />
                MAX SCOPE MODE
              </span>
            </label>
            <span style={{ fontSize: '11px', color: '#cc7733' }}>
              Bütün filtrləri söndürür, port scan + dead pool probe açır. Heç bir sub qaçmasın.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
