import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import StatCard from './components/StatCard';
import StatusBadge from './components/StatusBadge';
import IncidentTable from './components/IncidentTable';
import TelemetryCharts from './components/TelemetryCharts';
import WhyFlaggedModal from './components/WhyFlaggedModal';
import AdminPanel from './components/AdminPanel';
import {
  fetchHealth,
  fetchIncidents,
  fetchTelemetryMetrics,
  fetchTelemetryHistory,
  fetchDetectionStatus,
  fetchMitigationStatus,
  loginAdmin,
  checkSession,
  setAuthToken,
  setMitigationTier,
  blockIp,
  unblockIp,
  resetSystem,
  triggerHoneypot,
  sendSampleRequest,
  createDemoIncident,
} from './services/api';
import {
  Activity,
  ShieldCheck,
  Server,
  Layers,
  Send,
  PlusCircle,
  RefreshCw,
  Cpu,
  Wifi,
  Radio,
  Sliders,
  AlertTriangle,
} from 'lucide-react';

export default function App() {
  const [healthData, setHealthData] = useState(null);
  const [systemOnline, setSystemOnline] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [telemetry, setTelemetry] = useState(null);
  const [history, setHistory] = useState([]);
  const [detection, setDetection] = useState(null);
  const [mitigation, setMitigation] = useState(null);
  const [auth, setAuth] = useState({ authenticated: false });
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(false);
  
  // Interactive test request state
  const [lastResponse, setLastResponse] = useState(null);
  const [testingTraffic, setTestingTraffic] = useState(false);

  // Polling loop
  const pollTelemetry = async () => {
    try {
      const metrics = await fetchTelemetryMetrics();
      if (metrics) setTelemetry(metrics);
      const hist = await fetchTelemetryHistory();
      if (hist && hist.length > 0) setHistory(hist);
      const det = await fetchDetectionStatus();
      if (det) setDetection(det);
      const mit = await fetchMitigationStatus();
      if (mit) setMitigation(mit);
    } catch (err) {
      console.debug('Telemetry poll error:', err);
    }
  };

  const loadSystemState = async () => {
    setLoadingHealth(true);
    try {
      const h = await fetchHealth();
      setHealthData(h);
      setSystemOnline(h.status === 'healthy');
    } catch (err) {
      setSystemOnline(false);
    } finally {
      setLoadingHealth(false);
    }

    try {
      const inc = await fetchIncidents();
      setIncidents(inc);
      const sess = await checkSession();
      setAuth(sess);
    } catch (err) {
      console.error(err);
    }

    await pollTelemetry();
  };

  useEffect(() => {
    loadSystemState();
    const stateInterval = setInterval(loadSystemState, 10000);
    const telemetryInterval = setInterval(pollTelemetry, 3000);
    return () => {
      clearInterval(stateInterval);
      clearInterval(telemetryInterval);
    };
  }, []);

  const handleSendTraffic = async () => {
    setTestingTraffic(true);
    try {
      const res = await sendSampleRequest();
      setLastResponse(res);
      await pollTelemetry();
    } catch (err) {
      setLastResponse({ error: err.message || 'Failed to reach Nginx proxy' });
    } finally {
      setTestingTraffic(false);
    }
  };

  const handleLogin = async (username, password) => {
    try {
      const res = await loginAdmin(username, password);
      setAuth({ authenticated: true, username: res.username, role: res.role });
      alert('Authenticated successfully as Admin!');
    } catch (err) {
      alert('Login failed: ' + err.message);
    }
  };

  const handleLogout = () => {
    setAuthToken(null);
    setAuth({ authenticated: false });
  };

  const handleSetTier = async (tier) => {
    const res = await setMitigationTier(tier, 'Manual Operator Override');
    setMitigation(res);
  };

  const handleBlockIp = async (ip, reason) => {
    const res = await blockIp(ip, reason);
    if (res.mitigation_status) setMitigation(res.mitigation_status);
  };

  const handleUnblockIp = async (ip) => {
    const res = await unblockIp(ip);
    if (res.mitigation_status) setMitigation(res.mitigation_status);
  };

  const handleResetSystem = async () => {
    await resetSystem();
    setDetection({
      classification: "NORMAL",
      verdict_reason: "Metrics within baseline thresholds",
      url_entropy: 2.50,
      ip_entropy: 2.80,
      baseline_rps: 5.0
    });
    await loadSystemState();
    alert('System reset to baseline normal state.');
  };

  const handleRunSimulation = async (type) => {
    if (type === 'honeypot') {
      try {
        await triggerHoneypot();
        await blockIp("203.0.113.199", "Decoy Tripwire: Scanner accessed /admin-backup/");
        const newInc = await createDemoIncident("ATTACK", "TIER_2", {
          source_ip: "203.0.113.199",
          requests_per_sec: 1.0,
          baseline_rps: 5.0,
          url_entropy: 0.0,
          ip_entropy: 0.0,
          verdict_reason: "High-confidence tripwire: Adversary scanner accessed decoy /admin-backup/. Auto-blocked IP 203.0.113.199 in Tier 2."
        });
        setIncidents((prev) => [newInc, ...prev]);
        setDetection({
          classification: "ATTACK",
          verdict_reason: "Honeypot decoy tripwire breached by IP 203.0.113.199. Auto-blocked in Tier 2.",
          url_entropy: 0.0,
          ip_entropy: 0.0,
          baseline_rps: 5.0
        });
        await setMitigationTier("TIER_2", "Honeypot Decoy Tripwire Breach");
        await loadSystemState();
      } catch (err) {
        console.error("Honeypot simulation error:", err);
      }
    } else if (type === 'attack') {
      try {
        await blockIp("198.51.100.99", "Single-path HTTP Flood Attack Signature");
        const newInc = await createDemoIncident("ATTACK", "TIER_2", {
          source_ip: "198.51.100.99",
          requests_per_sec: 420.5,
          baseline_rps: 12.0,
          url_entropy: 0.35,
          ip_entropy: 0.95,
          verdict_reason: "High requests/sec surge with collapsed URL entropy. Single-path HTTP flood attack."
        });
        setIncidents((prev) => [newInc, ...prev]);
        setDetection({
          classification: "ATTACK",
          verdict_reason: "High requests/sec surge with collapsed URL entropy (0.35). Single-path flood signature.",
          url_entropy: 0.35,
          ip_entropy: 0.95,
          baseline_rps: 12.0
        });
        await setMitigationTier("TIER_2", "Simulated HTTP Flood Attack");
        await loadSystemState();
      } catch (err) {
        console.error("Attack simulation error:", err);
      }
    } else if (type === 'flash_crowd') {
      try {
        const newInc = await createDemoIncident("FLASH_CROWD", "TIER_3", {
          source_ip: "Diverse Cluster (50+ IPs)",
          requests_per_sec: 185.0,
          baseline_rps: 12.0,
          url_entropy: 2.85,
          ip_entropy: 2.92,
          verdict_reason: "Legitimate flash crowd detected: High RPS surge with high URL/IP entropy. Triggering Tier 3 Horizontal Scale-Out."
        });
        setIncidents((prev) => [newInc, ...prev]);
        setDetection({
          classification: "FLASH_CROWD",
          verdict_reason: "Legitimate flash crowd detected: High RPS surge with high entropy. Triggering Tier 3 Scale-Out.",
          url_entropy: 2.85,
          ip_entropy: 2.92,
          baseline_rps: 12.0
        });
        await setMitigationTier("TIER_3", "Simulated Legitimate Flash Crowd (Scale-Out)");
        await loadSystemState();
      } catch (err) {
        console.error("Flash crowd simulation error:", err);
      }
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      <Navbar systemOnline={systemOnline} serverNode={healthData?.server_node || 'N/A'} />

      {/* Hidden Honeypot Decoy Link for Scanners */}
      <a href="http://localhost:8080/admin-backup/" style={{ display: 'none' }} tabIndex={-1} aria-hidden="true">
        Decoy Admin Backup Archive
      </a>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        
        {/* Banner: System Status & Architecture Overview */}
        <div className="bg-gradient-to-r from-slate-800 to-slate-800/80 border border-slate-700/60 rounded-2xl p-6 shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center space-x-3 mb-2">
                <span className="text-xl font-bold tracking-tight text-white">CloudShield DDoS Mitigation Engine</span>
                <StatusBadge classification={detection?.classification || "NORMAL"} />
              </div>
              <p className="text-sm text-slate-400 max-w-2xl">
                Multi-Signal Analysis: <code className="text-sky-300 font-mono">Requests/sec</code> &bull; 
                <code className="text-purple-300 font-mono"> URL Entropy ({detection?.url_entropy?.toFixed(2) || '2.50'})</code> &bull; 
                <code className="text-sky-300 font-mono"> Source-IP Entropy ({detection?.ip_entropy?.toFixed(2) || '2.80'})</code> &bull; 
                <code className="text-amber-300 font-mono"> Decoy Tripwires</code>
              </p>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={loadSystemState}
                disabled={loadingHealth}
                className="flex items-center space-x-2 px-3 py-2 text-xs font-medium bg-slate-700/60 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-600 transition"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loadingHealth ? 'animate-spin' : ''}`} />
                <span>Refresh Status</span>
              </button>
            </div>
          </div>
        </div>

        {/* Live Telemetry Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          <StatCard
            title="Classification Verdict"
            value={detection?.classification || "NORMAL"}
            subtitle={detection?.verdict_reason || "Metrics within baseline thresholds"}
            icon={ShieldCheck}
            color={detection?.classification === 'ATTACK' ? 'rose' : detection?.classification === 'FLASH_CROWD' ? 'sky' : 'emerald'}
            badge={<StatusBadge classification={detection?.classification || "NORMAL"} />}
          />
          <StatCard
            title="Active Mitigation Tier"
            value={mitigation?.active_tier || "NONE"}
            subtitle={mitigation?.blocked_ip_count ? `${mitigation.blocked_ip_count} IPs blocked in Tier 2` : "No IP blocking or rate limiting active"}
            icon={Layers}
            color={mitigation?.active_tier !== 'NONE' ? 'amber' : 'sky'}
          />
          <StatCard
            title="Traffic Rate"
            value={`${telemetry?.requests_per_sec ?? 0} req/s`}
            subtitle={`Baseline: ${detection?.baseline_rps ?? 5.0} req/s`}
            icon={Activity}
            color="sky"
          />
          <StatCard
            title="URL Shannon Entropy"
            value={`${detection?.url_entropy?.toFixed(2) ?? '2.50'}`}
            subtitle={detection?.url_z_score ? `Z-Score: ${detection.url_z_score}` : "Baseline Spread: 2.50"}
            icon={Radio}
            color="purple"
          />
        </div>

        {/* Live Recharts Section */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <span>Real-Time Telemetry & Deviation Signals</span>
            </h2>
            <span className="text-xs text-slate-400 flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Updated every 3s via Prometheus</span>
            </span>
          </div>
          <TelemetryCharts history={history} />
        </div>

        {/* Incident History Table (Clickable for "Why Was This Flagged?") */}
        <div>
          <IncidentTable
            incidents={incidents}
            onSelectIncident={(inc) => setSelectedIncident(inc)}
          />
        </div>

        {/* Admin Control Panel */}
        <AdminPanel
          mitigationStatus={mitigation}
          onSetTier={handleSetTier}
          onBlockIp={handleBlockIp}
          onUnblockIp={handleUnblockIp}
          onResetSystem={handleResetSystem}
          onRunSimulation={handleRunSimulation}
          auth={auth}
          onLogin={handleLogin}
          onLogout={handleLogout}
        />

        {/* Interactive Lab Verification Controls */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-slate-800/60 border border-slate-700/60 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-white mb-2 flex items-center space-x-2">
              <Send className="w-4 h-4 text-sky-400" />
              <span>Ingress Test Probe: Send Traffic Through Nginx</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Send test requests directly through Nginx ingress (<code className="text-sky-300">http://localhost:8080/api/v1/sample/hello</code>).
            </p>

            <button
              onClick={handleSendTraffic}
              disabled={testingTraffic}
              className="flex items-center space-x-2 px-4 py-2 text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white rounded-lg transition shadow-md disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{testingTraffic ? 'Sending Request...' : 'Send Request through Nginx'}</span>
            </button>

            {lastResponse && (
              <div className="mt-4 bg-slate-900/90 border border-slate-700/80 rounded-lg p-4 font-mono text-xs text-slate-300 space-y-1">
                <div className="text-emerald-400 font-semibold mb-1 flex items-center justify-between">
                  <span>✓ Request Routed Successfully</span>
                  <span className="text-slate-400 font-normal">HTTP 200 OK</span>
                </div>
                <div><span className="text-slate-500">Upstream Worker:</span> <span className="text-sky-300 font-bold">{lastResponse.served_by || 'N/A'}</span></div>
                <div><span className="text-slate-500">Nginx Header (X-Served-By):</span> <span className="text-amber-300">{lastResponse.header_served_by || 'N/A'}</span></div>
                <div><span className="text-slate-500">Worker Request Counter:</span> #{lastResponse.request_number || 'N/A'}</div>
              </div>
            )}
          </div>

          <div className="bg-slate-800/60 border border-slate-700/60 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-white mb-2 flex items-center space-x-2">
              <Server className="w-4 h-4 text-emerald-400" />
              <span>Cluster & Database Status</span>
            </h3>
            <div className="space-y-3 text-xs mt-4">
              <div className="flex justify-between items-center p-2 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-slate-400">Database Connection</span>
                <span className="font-semibold text-emerald-400">{healthData?.database || 'Connected'}</span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-slate-400">Mitigation Tier</span>
                <span className="font-semibold text-amber-300">{mitigation?.active_tier || 'NONE'}</span>
              </div>
              <div className="flex justify-between items-center p-2 rounded bg-slate-900/60 border border-slate-800">
                <span className="text-slate-400">Blocked IP Count</span>
                <span className="font-semibold text-rose-400">{mitigation?.blocked_ip_count || 0}</span>
              </div>
            </div>
          </div>
        </div>

      </main>

      {/* "Why Was This Flagged?" Modal */}
      {selectedIncident && (
        <WhyFlaggedModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onUnblockIp={(ip) => {
            handleUnblockIp(ip);
            setSelectedIncident(null);
          }}
        />
      )}
    </div>
  );
}
