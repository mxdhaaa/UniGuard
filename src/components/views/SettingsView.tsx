import React, { useState } from 'react';
import { Settings, Key, Bell, Shield, Save, Check } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [webhookUrl, setWebhookUrl] = useState('');
  const [syslogHost, setSyslogHost] = useState('10.24.0.50:514');
  const [apiKey, setApiKey] = useState('ug_live_9f83a21bc9048e77412a');
  const [savedSuccess, setSavedSuccess] = useState(false);

  const handleSave = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="space-y-6 font-sans">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">System Settings</h1>
          <p className="text-xs text-slate-500 mt-1">
            Configure SIEM integrations, alerting webhooks, and API authentication tokens.
          </p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-800 hover:bg-teal-900 text-white rounded text-xs font-medium transition-colors shadow-xs"
        >
          {savedSuccess ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
          <span>{savedSuccess ? 'Settings Saved' : 'Save Changes'}</span>
        </button>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs space-y-6 max-w-3xl">
        {/* Alerting Webhooks */}
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Alerting & Notification Integrations</h3>
          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-700 font-medium mb-1">Slack / Webhook Endpoint</label>
              <input
                type="text"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                className="w-full p-2 bg-slate-50 border border-slate-200 rounded font-mono text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-teal-700"
              />
            </div>
            <div>
              <label className="block text-slate-700 font-medium mb-1">Syslog / SIEM Server Target (UDP/TCP)</label>
              <input
                type="text"
                value={syslogHost}
                onChange={(e) => setSyslogHost(e.target.value)}
                className="w-full p-2 bg-slate-50 border border-slate-200 rounded font-mono text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-teal-700"
              />
            </div>
          </div>
        </div>

        {/* API Tokens */}
        <div className="pt-4 border-t border-slate-200 space-y-3">
          <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">API Authentication Tokens</h3>
          <div className="space-y-3 text-xs">
            <div>
              <label className="block text-slate-700 font-medium mb-1">UniGuard Collector Ingestion Key</label>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={apiKey}
                  readOnly
                  className="flex-1 p-2 bg-slate-100 border border-slate-200 rounded font-mono text-xs text-slate-700 select-all"
                />
                <button
                  onClick={() => alert('API Key copied to clipboard')}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 rounded font-medium"
                >
                  Copy Key
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Data Retention */}
        <div className="pt-4 border-t border-slate-200 space-y-3">
          <h3 className="text-xs font-semibold text-slate-800 uppercase tracking-wider">Data Retention Policy</h3>
          <div className="flex items-center gap-4 text-xs">
            <span className="text-slate-700 font-medium">Passive PCAP & Feature Cache:</span>
            <select className="bg-white border border-slate-200 rounded py-1 px-2 text-slate-800">
              <option value="30">30 Days Retention</option>
              <option value="60">60 Days Retention</option>
              <option value="90">90 Days Retention</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};


