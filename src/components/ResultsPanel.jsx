import React, { useState, useMemo } from 'react';
import { Search, Download, Copy, ExternalLink, Check } from 'lucide-react';
import {
  exportAllSubdomains,
  exportLiveSubdomains,
  exportLive200,
  exportLiveCsv,
  exportJson
} from '../services/exportUtils';

export default function ResultsPanel({ subdomains = [], totalLiveCount = 0 }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [filter200, setFilter200] = useState(true);
  const [filter3xx, setFilter3xx] = useState(false);
  const [filter4xx, setFilter4xx] = useState(false);
  const [filter5xx, setFilter5xx] = useState(false);
  const [sortByRisk, setSortByRisk] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  // Filtr və sıralama
  const filteredItems = useMemo(() => {
    let result = [...subdomains];

    // Mətn axtarışı
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      result = result.filter(
        item =>
          item.subdomain.toLowerCase().includes(q) ||
          (item.finalUrl && item.finalUrl.toLowerCase().includes(q)) ||
          (item.ip && item.ip.includes(q)) ||
          (item.category && item.category.toLowerCase().includes(q))
      );
    }

    // Status kod filtrləri
    const anyStatusFilter = filter200 || filter3xx || filter4xx || filter5xx;
    if (anyStatusFilter) {
      result = result.filter(item => {
        const s = item.status;
        if (filter200 && s === 200) return true;
        if (filter3xx && s >= 300 && s < 400) return true;
        if (filter4xx && s >= 400 && s < 500) return true;
        if (filter5xx && s >= 500 && s < 600) return true;
        return false;
      });
    }

    // Riskə görə sırala
    if (sortByRisk) {
      const riskWeight = { CRITICAL: 4, HIGH: 3, MED: 2, LOW: 1, INFO: 0 };
      result.sort((a, b) => (riskWeight[b.risk] || 0) - (riskWeight[a.risk] || 0));
    }

    return result;
  }, [subdomains, searchQuery, filter200, filter3xx, filter4xx, filter5xx, sortByRisk]);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const displayedCount = filteredItems.length > 0 
    ? (totalLiveCount > 0 && filteredItems.length < totalLiveCount ? totalLiveCount : filteredItems.length)
    : 0;

  return (
    <div className="cyber-panel">
      <div className="section-header">
        <div className="section-title">
          <span>NƏTİCƏLƏR</span>
        </div>
      </div>

      {/* Filtr və Export Paneli */}
      <div className="results-filter-bar">
        <div className="results-filter-inputs">
          {/* Axtarış */}
          <div className="filter-search-box">
            <Search size={14} color="#00ff66" />
            <input
              type="text"
              className="filter-search-input"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="filtr: subdomain / title..."
            />
          </div>

          {/* Status Checkboxları */}
          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={filter200}
              onChange={(e) => setFilter200(e.target.checked)}
            />
            <span>200</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={filter3xx}
              onChange={(e) => setFilter3xx(e.target.checked)}
            />
            <span>3xx</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={filter4xx}
              onChange={(e) => setFilter4xx(e.target.checked)}
            />
            <span>4xx</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={filter5xx}
              onChange={(e) => setFilter5xx(e.target.checked)}
            />
            <span>5xx</span>
          </label>

          <label className="cyber-checkbox-label">
            <input
              type="checkbox"
              className="cyber-checkbox"
              checked={sortByRisk}
              onChange={(e) => setSortByRisk(e.target.checked)}
            />
            <span>Riskə görə sırala</span>
          </label>

          <span style={{ color: '#00ff66', fontWeight: 600, fontSize: '12px' }}>
            Göstərilən: {displayedCount.toLocaleString()}
          </span>
        </div>

        {/* Export Düymələri */}
        <div className="export-btn-group">
          <button
            type="button"
            className="cyber-btn btn-outline"
            onClick={() => exportAllSubdomains(subdomains)}
            title="Bütün tapılan subdomain siyahısını endir (.txt)"
          >
            [ all_subdomains.txt ]
          </button>

          <button
            type="button"
            className="cyber-btn btn-outline"
            onClick={() => exportLiveSubdomains(subdomains)}
            title="Yalnız canlı subdomain siyahısını endir (.txt)"
          >
            [ live_subdomains.txt ]
          </button>

          <button
            type="button"
            className="cyber-btn"
            style={{ borderColor: '#00ff66', boxShadow: '0 0 6px rgba(0, 255, 102, 0.4)' }}
            onClick={() => exportLive200(subdomains)}
            title="Yalnız HTTP 200 qayıdanları endir (.txt)"
          >
            [ live_200.txt ]
          </button>

          <button
            type="button"
            className="cyber-btn btn-outline"
            onClick={() => exportLiveCsv(subdomains)}
            title="CSV hesabatını endir (.csv)"
          >
            [ live_results.csv ]
          </button>

          <button
            type="button"
            className="cyber-btn btn-outline"
            onClick={() => exportJson(subdomains)}
            title="JSON çıxışını endir"
          >
            <Download size={12} />
            JSON
          </button>
        </div>
      </div>

      {/* Cyber Cədvəl */}
      <div className="results-table-wrap">
        <table className="cyber-table">
          <thead>
            <tr>
              <th style={{ width: '40%' }}>SUBDOMAIN</th>
              <th style={{ width: '8%' }}>STATUS</th>
              <th style={{ width: '8%' }}>KATEQORİYA</th>
              <th style={{ width: '8%' }}>RİSK</th>
              <th style={{ width: '12%' }}>IP</th>
              <th style={{ width: '24%' }}>FINAL URL</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '36px', color: '#274c30' }}>
                  {subdomains.length === 0
                    ? 'Hələ heç bir nəticə tapılmadı. Skanlamaq üçün yuxarıdakı "BAŞLAT" düyməsinə klikləyin.'
                    : 'Filtrə uyğun nəticə tapılmadı.'}
                </td>
              </tr>
            ) : (
              filteredItems.map((item, idx) => {
                const rowKey = `${item.subdomain}-${idx}`;
                const statusClass =
                  item.status === 200
                    ? 'status-200'
                    : item.status >= 300 && item.status < 400
                    ? 'status-3xx'
                    : item.status >= 400 && item.status < 500
                    ? 'status-4xx'
                    : 'status-5xx';

                const riskClass =
                  item.risk === 'CRITICAL'
                    ? 'risk-critical'
                    : item.risk === 'HIGH'
                    ? 'risk-high'
                    : item.risk === 'MED'
                    ? 'risk-med'
                    : 'risk-low';

                return (
                  <tr key={rowKey}>
                    {/* Subdomain */}
                    <td className="table-subdomain">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>{item.subdomain}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(item.subdomain, `sub-${idx}`)}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            color: copiedId === `sub-${idx}` ? '#00ff66' : '#274c30',
                            padding: '2px'
                          }}
                          title="Subdomain-i kopyala"
                        >
                          {copiedId === `sub-${idx}` ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                    </td>

                    {/* Status */}
                    <td>
                      <span className={`status-badge ${statusClass}`}>
                        {item.status}
                      </span>
                    </td>

                    {/* Kateqoriya */}
                    <td>
                      <span style={{ color: '#4d8059', fontSize: '11px', fontWeight: 600 }}>
                        {item.category || '-'}
                      </span>
                    </td>

                    {/* Risk */}
                    <td>
                      {item.risk ? (
                        <span className={`risk-tag ${riskClass}`}>
                          {item.risk}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>

                    {/* IP */}
                    <td>
                      <span style={{ color: '#5b8c66' }}>
                        {item.ip || '-'}
                      </span>
                    </td>

                    {/* Final URL */}
                    <td>
                      {item.finalUrl ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <a
                            href={item.finalUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="url-link"
                          >
                            {item.finalUrl}
                          </a>
                          <ExternalLink size={11} color="#386d44" />
                        </div>
                      ) : (
                        '-'
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
