import React, { useState, useEffect } from 'react';
import { Key, X, Check, Save, ExternalLink } from 'lucide-react';

const API_CONFIG_FIELDS = [
  {
    id: 'securitytrails_api_key',
    name: 'SecurityTrails',
    hint: 'Canlı və tarixi subdomain bazası',
    url: 'https://securitytrails.com/app/account/credentials'
  },
  {
    id: 'shodan_api_key',
    name: 'Shodan',
    hint: 'DNS məlumatları və açıq portlar',
    url: 'https://account.shodan.io/'
  },
  {
    id: 'zoomeye_api_key',
    name: 'ZoomEye',
    hint: 'Kiber kəşfiyyat və aktiv axtarışı',
    url: 'https://www.zoomeye.org/profile'
  },
  {
    id: 'virustotal_api_key',
    name: 'VirusTotal',
    hint: 'Passiv DNS telemetriyası və subdomainlər',
    url: 'https://www.virustotal.com/gui/user/apiKey'
  },
  {
    id: 'chaos_api_key',
    name: 'Chaos (ProjectDiscovery)',
    hint: 'ProjectDiscovery bug bounty aktiv arxivi',
    url: 'https://chaos.projectdiscovery.io/'
  },
  {
    id: 'github_token',
    name: 'GitHub Token',
    hint: 'GitHub kodlarında gizli subdomain və açarlar',
    url: 'https://github.com/settings/tokens'
  }
];

export default function ApiKeysModal({ isOpen, onClose, onKeysUpdated }) {
  const [formData, setFormData] = useState({});
  const [activeStatus, setActiveStatus] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetch('http://127.0.0.1:8000/api/config')
        .then(res => res.json())
        .then(data => {
          setFormData(data.keys || {});
          setActiveStatus(data.active_status || {});
        })
        .catch(() => {});
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleChange = (id, val) => {
    setFormData(prev => ({ ...prev, [id]: val }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      if (res.ok) {
        setSaveSuccess(true);
        if (onKeysUpdated) onKeysUpdated();
        setTimeout(() => {
          setSaveSuccess(false);
          onClose();
        }, 800);
      }
    } catch {
      alert('Key-lər yadda saxlanılarkən xəta baş verdi!');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100vw',
      height: '100vh',
      backgroundColor: 'rgba(2, 6, 3, 0.85)',
      backdropFilter: 'blur(6px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999
    }}>
      <div style={{
        width: '680px',
        maxWidth: '92vw',
        maxHeight: '90vh',
        overflowY: 'auto',
        background: '#060d08',
        border: '1px solid #1e5c2b',
        boxShadow: '0 0 25px rgba(0, 255, 102, 0.25)',
        borderRadius: '6px',
        padding: '24px',
        fontFamily: 'var(--font-mono)'
      }}>
        {/* Başlıq */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid #13381a',
          paddingBottom: '14px',
          marginBottom: '18px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Key size={18} color="#00ff66" />
            <span style={{ fontSize: '15px', fontWeight: 800, color: '#00ff66', letterSpacing: '1px' }}>
              4Lizz Recon // API KEYS & MƏNBƏLƏR
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              cursor: 'pointer',
              color: '#44774e'
            }}
          >
            <X size={18} />
          </button>
        </div>

        <p style={{ color: '#77a880', fontSize: '12px', marginBottom: '20px', lineHeight: 1.5 }}>
          Shodan, SecurityTrails, ZoomEye, VirusTotal və Chaos kimi mənbələr üçün API key lazımdır. 
          Key əlavə etdikdə həmin modulun <strong>LED işığı yaşıl yanacaq</strong> və nəticələrin sayı kəskin artacaq.
        </p>

        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {API_CONFIG_FIELDS.map(field => {
            const isConfigured = !!activeStatus[field.id];
            return (
              <div
                key={field.id}
                style={{
                  background: '#08140b',
                  border: `1px solid ${isConfigured ? '#1b5e2b' : '#142c19'}`,
                  borderRadius: '4px',
                  padding: '10px 14px'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span
                      style={{
                        width: '8px',
                        height: '8px',
                        borderRadius: '50%',
                        backgroundColor: isConfigured ? '#00ff66' : '#772020',
                        boxShadow: isConfigured ? '0 0 6px #00ff66' : 'none'
                      }}
                    />
                    <label style={{ color: '#00ff66', fontWeight: 700, fontSize: '12px' }}>
                      {field.name}
                    </label>
                  </div>
                  <a
                    href={field.url}
                    target="_blank"
                    rel="noreferrer"
                    style={{
                      color: '#44774e',
                      fontSize: '11px',
                      textDecoration: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px'
                    }}
                  >
                    <span>Key Al</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <input
                  type="password"
                  placeholder={isConfigured ? '•••••••••••••••• (Aktivdir)' : `${field.name} API key-i daxil edin...`}
                  value={formData[field.id] || ''}
                  onChange={(e) => handleChange(field.id, e.target.value)}
                  style={{
                    width: '100%',
                    background: '#040805',
                    border: '1px solid #14351a',
                    padding: '7px 10px',
                    borderRadius: '3px',
                    color: '#c4f0cc',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    outline: 'none'
                  }}
                />
                <div style={{ color: '#44774e', fontSize: '10px', marginTop: '4px' }}>
                  {field.hint}
                </div>
              </div>
            );
          })}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
            <button
              type="button"
              className="cyber-btn btn-outline"
              onClick={onClose}
            >
              BAĞLA
            </button>
            <button
              type="submit"
              className="cyber-btn"
              disabled={saving}
              style={{ minWidth: '110px', justifyContent: 'center' }}
            >
              {saveSuccess ? (
                <>
                  <Check size={14} />
                  YADDA SAXLANILDI
                </>
              ) : (
                <>
                  <Save size={14} />
                  {saving ? 'YADDA SAXLANILIR...' : 'YADDA SAXLA'}
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
