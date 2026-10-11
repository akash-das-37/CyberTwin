import { useCallback, useEffect, useState } from 'react';
import type { Settings } from '../types';
import { storageService } from '../storage/storageService';
import './options.css';

export function Options() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [trustedContacts, setTrustedContacts] = useState<string[]>([]);
  const [trustedDomains, setTrustedDomains] = useState<string[]>([]);
  const [newContact, setNewContact] = useState('');
  const [newDomain, setNewDomain] = useState('');
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    const data = await storageService.getAll();
    setSettings(data.settings);
    setTrustedContacts(data.trustedContacts);
    setTrustedDomains(data.trustedDomains);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const saveSettings = async (partial: Partial<Settings>) => {
    const updated = await storageService.updateSettings(partial);
    setSettings(updated);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const addContact = async () => {
    if (!newContact.trim()) return;
    const list = await storageService.addTrustedContact(newContact);
    setTrustedContacts(list);
    setNewContact('');
  };

  const removeContact = async (email: string) => {
    const list = await storageService.removeTrustedContact(email);
    setTrustedContacts(list);
  };

  const addDomain = async () => {
    if (!newDomain.trim()) return;
    const list = await storageService.addTrustedDomain(newDomain);
    setTrustedDomains(list);
    setNewDomain('');
  };

  const removeDomain = async (domain: string) => {
    const list = await storageService.removeTrustedDomain(domain);
    setTrustedDomains(list);
  };

  const clearProfile = async () => {
    await storageService.clearBehaviorProfile();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const clearHistory = async () => {
    await storageService.clearScanHistory();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  if (!settings) {
    return (
      <div className="options-root cyber-grid-bg flex items-center justify-center min-h-screen">
        <div className="ct-spinner" />
      </div>
    );
  }

  return (
    <div className="options-root cyber-grid-bg min-h-screen p-8">
      <div className="max-w-2xl mx-auto space-y-6">
        <header className="options-header">
          <h1>🛡️ CyberTwin AI Settings</h1>
          <p>Configure your digital trust guardian</p>
          {saved && <span className="saved-badge">✓ Saved</span>}
        </header>

        <section className="glass-card options-section">
          <h2>Analysis</h2>
          <label className="toggle-row">
            <span>Auto-scan emails on open</span>
            <input
              type="checkbox"
              checked={settings.autoScan}
              onChange={(e) => saveSettings({ autoScan: e.target.checked })}
            />
          </label>
          <label className="toggle-row">
            <span>Privacy mode (mask PII before analysis)</span>
            <input
              type="checkbox"
              checked={settings.privacyMode}
              onChange={(e) => saveSettings({ privacyMode: e.target.checked })}
            />
          </label>
          <label className="toggle-row">
            <span>Local-only analysis (no backend)</span>
            <input
              type="checkbox"
              checked={settings.localOnlyAnalysis}
              onChange={(e) => saveSettings({ localOnlyAnalysis: e.target.checked })}
            />
          </label>
          <label className="field-row">
            <span>API Endpoint (FastAPI backend)</span>
            <input
              className="input-cyber"
              value={settings.apiEndpoint}
              onChange={(e) => saveSettings({ apiEndpoint: e.target.value })}
              placeholder="http://localhost:8000"
            />
          </label>
          <label className="field-row">
            <span>Expertise Level</span>
            <select
              className="input-cyber"
              value={settings.expertiseLevel}
              onChange={(e) =>
                saveSettings({
                  expertiseLevel: e.target.value as Settings['expertiseLevel'],
                })
              }
            >
              <option value="beginner">Beginner</option>
              <option value="intermediate">Intermediate</option>
              <option value="expert">Expert</option>
            </select>
          </label>
        </section>

        <section className="glass-card options-section">
          <h2>Trusted Contacts</h2>
          <div className="add-row">
            <input
              className="input-cyber flex-1"
              value={newContact}
              onChange={(e) => setNewContact(e.target.value)}
              placeholder="email@company.com"
            />
            <button className="btn-primary" onClick={addContact}>
              Add
            </button>
          </div>
          <ul className="trust-list">
            {trustedContacts.map((c) => (
              <li key={c}>
                <span>{c}</span>
                <button onClick={() => removeContact(c)}>Remove</button>
              </li>
            ))}
            {trustedContacts.length === 0 && (
              <li className="empty">No trusted contacts yet</li>
            )}
          </ul>
        </section>

        <section className="glass-card options-section">
          <h2>Trusted Domains</h2>
          <div className="add-row">
            <input
              className="input-cyber flex-1"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="company.com"
            />
            <button className="btn-primary" onClick={addDomain}>
              Add
            </button>
          </div>
          <ul className="trust-list">
            {trustedDomains.map((d) => (
              <li key={d}>
                <span>{d}</span>
                <button onClick={() => removeDomain(d)}>Remove</button>
              </li>
            ))}
            {trustedDomains.length === 0 && (
              <li className="empty">No trusted domains yet</li>
            )}
          </ul>
        </section>

        <section className="glass-card options-section">
          <h2>Behavior Profile</h2>
          <p className="section-desc">
            CyberTwin learns your communication patterns locally to detect anomalies.
          </p>
          <div className="flex gap-4 mt-4">
            <button className="btn-secondary danger" onClick={clearProfile}>
              Clear Stored Behavior Profile
            </button>
            <button className="btn-secondary danger" onClick={clearHistory}>
              Clear Scan History
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}

export default Options;
