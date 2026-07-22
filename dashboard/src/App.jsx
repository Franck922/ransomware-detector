import React, { useState, useEffect } from 'react';
import { 
  Activity, Shield, Terminal, AlertTriangle, FileText, Settings, 
  Brain, CheckCircle, XCircle, Network, RefreshCw, ChevronRight, 
  Eye, ShieldAlert, Users, List, Play, FileCheck, HelpCircle, HardDrive
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, 
  ResponsiveContainer, PieChart, Pie, Cell
} from 'recharts';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [alerts, setAlerts] = useState([]);
  const [sysStatus, setSysStatus] = useState({
    status: "offline",
    ml_enabled: false,
    baseline_trained: false,
    pending_commands_count: 0
  });
  
  // Navigation states
  const [selectedTerminal, setSelectedTerminal] = useState("VM-WIN10-LAB");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  
  // Exclusions (Mock Data)
  const [exclusions, setExclusions] = useState([
    { id: 1, type: "Folder", path: "C:\\Program Files\\Git\\", comment: "Bruit de renommages Git ignore" },
    { id: 2, type: "Process", path: "C:\\Windows\\System32\\svchost.exe", comment: "Processus systeme de confiance" }
  ]);
  const [newExclusionPath, setNewExclusionPath] = useState("");
  const [newExclusionType, setNewExclusionType] = useState("Folder");

  // Simulation Sandbox
  const [sandboxFile, setSandboxFile] = useState("");
  const [sandboxResult, setSandboxResult] = useState(null);
  const [sandboxLoading, setSandboxLoading] = useState(false);

  // Polling API
  const fetchData = async () => {
    try {
      const resStatus = await fetch('http://localhost:8000/status');
      if (resStatus.ok) {
        const data = await resStatus.json();
        setSysStatus(data);
      }

      const resAlerts = await fetch('http://localhost:8000/alerts');
      if (resAlerts.ok) {
        const data = await resAlerts.json();
        setAlerts(data.alerts || []);
        if (data.alerts && data.alerts.length > 0) {
          if (!selectedAlert) setSelectedAlert(data.alerts[0].kill_payload);
          if (!selectedReport) setSelectedReport(data.alerts[0].kill_payload);
        }
      }
    } catch (error) {
      console.error("Erreur de liaison API EDR:", error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleKill = async (pid) => {
    try {
      const res = await fetch(`http://localhost:8000/response/kill/${pid}`, { method: 'POST' });
      if (res.ok) {
        alert(`Ordre de KILL transmis avec succes pour le PID ${pid}`);
        fetchData();
      }
    } catch (e) {
      alert("Erreur de communication.");
    }
  };

  const handleIsolate = async () => {
    try {
      const res = await fetch('http://localhost:8000/response/isolate', { method: 'POST' });
      if (res.ok) {
        alert("Ordre d'isolation reseau transmis avec succes.");
        fetchData();
      }
    } catch (e) {
      alert("Erreur de communication.");
    }
  };

  const handleRunSandbox = () => {
    if (!sandboxFile) return;
    setSandboxLoading(true);
    setTimeout(() => {
      setSandboxLoading(false);
      // Fausse analyse d'entropie
      const isRansom = sandboxFile.toLowerCase().endsWith(".exe") && sandboxFile.length > 12;
      setSandboxResult({
        entropy: isRansom ? 6.21 : 3.12,
        score: isRansom ? 85 : 15,
        decision: isRansom ? "SUSPECT (Ransomware Profil A)" : "SAIN (Normal)"
      });
    }, 1500);
  };

  // Recharts Chart Data
  const chartData = [
    { name: '-90', files: 2, entropy: 1.2 },
    { name: '-80', files: 5, entropy: 1.5 },
    { name: '-70', files: 1, entropy: 1.1 },
    { name: '-60', files: 3, entropy: 1.4 },
    { name: '-50', files: 2, entropy: 1.2 },
    { name: '-40', files: alerts.length > 0 ? 231 : 2, entropy: alerts.length > 0 ? 5.68 : 1.2 },
    { name: '-30', files: 0, entropy: 1.0 },
    { name: '-20', files: 0, entropy: 1.0 },
    { name: '-10', files: 1, entropy: 1.2 },
    { name: '0', files: 3, entropy: 1.1 }
  ];

  const pieData = [
    { name: 'Création', value: 231, color: '#dc2626' },
    { name: 'Suppression', value: 0, color: '#ca8a04' },
    { name: 'Processus', value: 1, color: '#0f172a' }
  ];

  return (
    <div className="flex min-h-screen bg-bg-main text-text-main font-sans antialiased">
      
      {/* SIDEBAR */}
      <aside className="w-64 bg-bg-sidebar border-r border-border flex flex-col fixed h-screen z-10 overflow-y-auto">
        <div className="p-6 flex items-center gap-3">
          <div className="w-8 h-8 bg-brand-primary rounded flex items-center justify-center font-bold text-white text-sm">
            EDR
          </div>
          <span className="font-semibold text-base tracking-tight">SOC Console</span>
        </div>

        {/* CATEGORIES NAV */}
        <div className="flex-1 px-4 space-y-6">
          {/* CATEGORY 1: MONITORING */}
          <div>
            <span className="px-4 text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-2">Surveillance</span>
            <div className="space-y-1">
              <button 
                onClick={() => setActiveTab('overview')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'overview' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>Dashboard</span>
              </button>
              <button 
                onClick={() => setActiveTab('terminals')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'terminals' || activeTab === 'terminal_detail' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Terminal className="w-4 h-4" />
                <span>Terminaux</span>
              </button>
            </div>
          </div>

          {/* CATEGORY 2: INCIDENT RESPONSE */}
          <div>
            <span className="px-4 text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-2">Reponse aux Incidents</span>
            <div className="space-y-1">
              <button 
                onClick={() => setActiveTab('alerts')} 
                className={`w-full flex items-center justify-between px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'alerts' || activeTab === 'alert_detail' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Alertes de Securite</span>
                </div>
                {alerts.length > 0 && (
                  <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-brand-dangerGlow text-brand-danger">
                    {alerts.length}
                  </span>
                )}
              </button>
              <button 
                onClick={() => setActiveTab('reports')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'reports' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <FileText className="w-4 h-4" />
                <span>Rapports Forensics</span>
              </button>
              <button 
                onClick={() => setActiveTab('response_logs')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'response_logs' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <ShieldAlert className="w-4 h-4" />
                <span>Journal des Réponses</span>
              </button>
            </div>
          </div>

          {/* CATEGORY 3: ANALYSIS & ENGINES */}
          <div>
            <span className="px-4 text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-2">Analyse & Moteurs</span>
            <div className="space-y-1">
              <button 
                onClick={() => setActiveTab('ml_insights')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'ml_insights' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Brain className="w-4 h-4" />
                <span>Statistiques ML</span>
              </button>
              <button 
                onClick={() => setActiveTab('rules_config')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'rules_config' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <List className="w-4 h-4" />
                <span>Moteur Heuristique</span>
              </button>
              <button 
                onClick={() => setActiveTab('sandbox')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'sandbox' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Play className="w-4 h-4" />
                <span>Analyseur de Fichier</span>
              </button>
            </div>
          </div>

          {/* CATEGORY 4: ADMIN */}
          <div>
            <span className="px-4 text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-2">Configuration & Outils</span>
            <div className="space-y-1">
              <button 
                onClick={() => setActiveTab('exclusions')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'exclusions' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <CheckCircle className="w-4 h-4" />
                <span>Regles d'Exclusion</span>
              </button>
              <button 
                onClick={() => setActiveTab('audit_logs')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'audit_logs' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <FileCheck className="w-4 h-4" />
                <span>Audit Logs</span>
              </button>
              <button 
                onClick={() => setActiveTab('team')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'team' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Users className="w-4 h-4" />
                <span>Equipe SOC</span>
              </button>
              <button 
                onClick={() => setActiveTab('settings')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'settings' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <Settings className="w-4 h-4" />
                <span>Configuration</span>
              </button>
              <button 
                onClick={() => setActiveTab('docs')} 
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                  activeTab === 'docs' ? 'bg-brand-primaryGlow text-brand-primary font-semibold' : 'text-text-muted hover:bg-gray-50'
                }`}
              >
                <HelpCircle className="w-4 h-4" />
                <span>Documentation EDR</span>
              </button>
            </div>
          </div>
        </div>

        <div className="p-4 border-t border-border mt-auto">
          <div className="flex items-center gap-2.5 text-xs text-text-muted font-medium">
            <span className={`w-2 h-2 rounded-full ${sysStatus.status === 'online' ? 'bg-brand-success animate-pulse' : 'bg-brand-danger'}`}></span>
            <span>EDR Daemon Online</span>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="ml-64 flex-1 p-10 min-h-screen">
        
        {/* HEADER */}
        <header className="flex justify-between items-center mb-8 border-b border-border pb-5">
          <div>
            <h1 className="text-xl font-bold tracking-tight">
              {activeTab === 'overview' && 'Vue d\'ensemble du SOC'}
              {activeTab === 'terminals' && 'Terminaux Surveilles'}
              {activeTab === 'terminal_detail' && `Terminal: ${selectedTerminal}`}
              {activeTab === 'alerts' && 'Journal des Alertes'}
              {activeTab === 'alert_detail' && 'Analyse Forensics de l\'Alerte'}
              {activeTab === 'reports' && 'Rapports d\'Incidents Forensics'}
              {activeTab === 'response_logs' && 'Journal des Réponses Actives'}
              {activeTab === 'ml_insights' && 'Performances et Feature Importance ML'}
              {activeTab === 'rules_config' && 'Gestion du Moteur Heuristique'}
              {activeTab === 'sandbox' && 'Analyseur de Fichier (Sandbox)'}
              {activeTab === 'exclusions' && 'Regles d\'Exclusion du Moteur'}
              {activeTab === 'audit_logs' && 'Journal d\'Audit des Analystes'}
              {activeTab === 'team' && 'Membres de l\'Equipe SOC'}
              {activeTab === 'settings' && 'Configuration Systemse EDR'}
              {activeTab === 'docs' && 'Guide de Reference Systemse'}
            </h1>
            <p className="text-xs text-text-muted mt-1">
              {activeTab === 'overview' && 'Indicateurs de compromission et activites globales'}
              {activeTab === 'terminals' && 'Liste des endpoints Windows surveilles par l\'Agent'}
              {activeTab === 'terminal_detail' && 'Visualisation des indicateurs de charge et connexions reseau'}
              {activeTab === 'alerts' && 'Compilations des anomalies detectees en cours'}
              {activeTab === 'alert_detail' && 'Arbre de causalite Sysmon et justifications'}
              {activeTab === 'reports' && 'Archives forensics au format JSON pour audits'}
              {activeTab === 'response_logs' && 'Historique des executions de Stop-Process et d\'isolation'}
              {activeTab === 'ml_insights' && 'Visualisation du score F1 et matrice du Random Forest'}
              {activeTab === 'rules_config' && 'Calibrage des scores affectes aux regles Sysmon'}
              {activeTab === 'sandbox' && 'Calcul instantane d\'entropie et suspicion'}
              {activeTab === 'exclusions' && 'Dossiers et processus exclus de la surveillance'}
              {activeTab === 'audit_logs' && 'Tracabilite des interventions SOC des analystes'}
              {activeTab === 'team' && 'Gestion des roles d\'equipe SOC N1, N2, N3'}
              {activeTab === 'settings' && 'Parametres reseau, polling et fenetrage temporel'}
              {activeTab === 'docs' && 'Documentation et Runbooks d\'incidents intégrés'}
            </p>
          </div>
          <button onClick={fetchData} className="btn btn-outline">
            <RefreshCw className="w-3.5 h-3.5" />
            Rafraichir
          </button>
        </header>

        {/* ====================================================================
            TAB: OVERVIEW
           ==================================================================== */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            <div className="grid grid-cols-4 gap-5">
              <div className="card-stat">
                <span className="stat-label">Terminaux</span>
                <span className="stat-value">1</span>
                <span className="stat-desc text-brand-success">● VM-WIN10-LAB</span>
              </div>
              <div className="card-stat">
                <span className="stat-label">Alertes Actives</span>
                <span className="stat-value">{alerts.length}</span>
                <span className="stat-desc text-brand-danger">
                  {alerts.length > 0 ? `▲ ${alerts.length} critiques` : '✓ Systemes calmes'}
                </span>
              </div>
              <div className="card-stat">
                <span className="stat-label">Rapports Genere</span>
                <span className="stat-value">{alerts.length}</span>
                <span className="stat-desc text-text-muted">reports/ archivés</span>
              </div>
              <div className="card-stat">
                <span className="stat-label">Moteur IA</span>
                <span className="stat-value">{sysStatus.ml_enabled ? 'Active' : 'Offline'}</span>
                <span className="stat-desc text-brand-success">Random Forest Charge</span>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 panel">
                <h3 className="panel-title mb-6">Activites Fichiers & Entropie (Glissant 10s)</h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                      <XAxis dataKey="name" stroke="#94a3b8" style={{ fontSize: 10 }} label={{ value: "Chronologie (secondes glissantes)", position: 'insideBottom', offset: -5, style: { fontSize: 10, fill: '#94a3b8', fontWeight: 600 } }} height={40} />
                      <YAxis stroke="#94a3b8" style={{ fontSize: 10 }} />
                      <Tooltip />
                      <Area type="monotone" dataKey="files" stroke="#dc2626" fillOpacity={0.04} fill="#fef2f2" name="Fichiers" />
                      <Area type="monotone" dataKey="entropy" stroke="#2563eb" fillOpacity={0.04} fill="#eff6ff" name="Entropie (x10)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="panel flex flex-col justify-between">
                <h3 className="panel-title text-center">Niveau de Risque Global</h3>
                <div className="flex flex-col items-center justify-center">
                  <div className={`w-32 h-32 rounded-full border-4 flex flex-col items-center justify-center ${
                    alerts.length > 0 
                      ? 'border-brand-danger text-brand-danger bg-brand-dangerGlow' 
                      : 'border-brand-success text-brand-success bg-brand-successGlow'
                  }`}>
                    <span className="text-3xl font-bold">{alerts.length > 0 ? '92%' : '0%'}</span>
                    <span className="text-[9px] font-bold tracking-widest uppercase mt-1">
                      {alerts.length > 0 ? 'Danger' : 'Sain'}
                    </span>
                  </div>
                  <span className="text-xs text-text-muted font-medium mt-6 text-center">
                    {alerts.length > 0 ? 'Attaque Ransomware neutralisee' : 'Aucun signal suspect'}
                  </span>
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="flex justify-between items-center mb-6">
                <h3 className="panel-title">Dernières Alertes</h3>
                <button onClick={() => setActiveTab('alerts')} className="btn btn-outline">Voir tout</button>
              </div>
              <div className="table-container">
                <table className="custom-table">
                  <thead>
                    <tr>
                      <th>Horodatage</th>
                      <th>Processus</th>
                      <th>PID</th>
                      <th>Score</th>
                      <th>Confidence</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="text-center text-text-muted py-6">Aucune alerte récente.</td>
                      </tr>
                    ) : (
                      alerts.map((a, i) => (
                        <tr key={i}>
                          <td>{a.timestamp || 'Aujourd\'hui'}</td>
                          <td className="font-semibold text-brand-danger">{a.kill_payload?.process}</td>
                          <td><span className="code-text">{a.kill_payload?.pid}</span></td>
                          <td><span className="badge badge-danger">{a.kill_payload?.score}</span></td>
                          <td><span className="badge badge-success">{a.kill_payload?.confidence}</span></td>
                          <td><span className="badge badge-success">PROCESSUS TUE</span></td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: TERMINALS
           ==================================================================== */}
        {activeTab === 'terminals' && (
          <div className="space-y-6">
            <div className="panel flex items-center justify-between p-8">
              <div className="flex items-center gap-6">
                <div className="w-14 h-14 bg-gray-50 border border-border rounded-xl flex items-center justify-center text-2xl shadow-sm">
                  🖥️
                </div>
                <div>
                  <h3 className="font-bold text-base">VM-WIN10-LAB</h3>
                  <p className="text-xs text-text-muted">192.168.10.10 • Windows 10 Pro</p>
                  <div className="flex gap-2 mt-2">
                    <span className="badge badge-success">Télémétrie Sysmon</span>
                    <span className="badge badge-success">Agent Active</span>
                  </div>
                </div>
              </div>
              <div className="flex gap-3">
                <button onClick={() => setActiveTab('terminal_detail')} className="btn btn-outline">
                  <Eye className="w-4 h-4" /> Inspecter la machine
                </button>
                <button onClick={handleIsolate} className="btn btn-danger">Isoler du Réseau</button>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: TERMINAL DETAIL
           ==================================================================== */}
        {activeTab === 'terminal_detail' && (
          <div className="space-y-6">
            <div className="flex gap-4">
              <button onClick={() => setActiveTab('terminals')} className="btn btn-outline">← Retour aux terminaux</button>
            </div>
            
            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2 panel">
                <h3 className="panel-title mb-6">Indicateurs de Charge de VM-WIN10-LAB</h3>
                <div className="grid grid-cols-3 gap-6">
                  <div className="border border-border rounded-lg p-5">
                    <span className="text-[10px] font-bold text-text-muted block mb-1 uppercase">Utilisation CPU</span>
                    <div className="text-2xl font-bold">8%</div>
                    <span className="text-[10px] text-text-muted">2 vCPUs configurés</span>
                  </div>
                  <div className="border border-border rounded-lg p-5">
                    <span className="text-[10px] font-bold text-text-muted block mb-1 uppercase">Utilisation RAM</span>
                    <div className="text-2xl font-bold">2.1 / 4.0 Go</div>
                    <span className="text-[10px] text-text-muted">Mémoire vive VM</span>
                  </div>
                  <div className="border border-border rounded-lg p-5">
                    <span className="text-[10px] font-bold text-text-muted block mb-1 uppercase">Statut Réseau</span>
                    <div className="text-2xl font-bold text-brand-success">Connecté</div>
                    <span className="text-[10px] text-text-muted">Custom (VMnet1)</span>
                  </div>
                </div>
              </div>

              <div className="panel">
                <h3 className="panel-title mb-6">Stockage Disque C:</h3>
                <div className="space-y-4">
                  <div className="flex justify-between text-xs">
                    <span>Espace occupé : 18.2 Go</span>
                    <span>Total : 40 Go</span>
                  </div>
                  <div className="h-3 bg-gray-100 border border-border rounded-full overflow-hidden">
                    <div className="h-full bg-brand-primary" style={{ width: '45.5%' }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: ALERTS
           ==================================================================== */}
        {activeTab === 'alerts' && (
          <div className="space-y-6">
            {alerts.length === 0 ? (
              <div className="panel text-center text-text-muted py-12">Aucune alerte. Le système est protégé.</div>
            ) : (
              alerts.map((a, i) => (
                <div key={i} className="panel border-l-4 border-brand-danger flex justify-between items-center">
                  <div>
                    <div className="flex items-center gap-3">
                      <span className="badge badge-danger">CRITIQUE</span>
                      <h3 className="font-bold text-sm text-brand-danger">{a.kill_payload?.process} (PID: {a.kill_payload?.pid})</h3>
                    </div>
                    <div className="text-xs text-text-muted mt-2">
                      Horodatage : {a.timestamp} • Score : {a.kill_payload?.score}/100
                    </div>
                  </div>
                  <button 
                    onClick={() => {
                      setSelectedAlert(a.kill_payload);
                      setActiveTab('alert_detail');
                    }} 
                    className="btn btn-outline"
                  >
                    Examiner
                  </button>
                </div>
              ))
            )}
          </div>
        )}

        {/* ====================================================================
            TAB: ALERT DETAIL
           ==================================================================== */}
        {activeTab === 'alert_detail' && (
          <div className="space-y-6">
            <button onClick={() => setActiveTab('alerts')} className="btn btn-outline">← Retour aux alertes</button>
            
            {selectedAlert ? (
              <div className="grid grid-cols-3 gap-6">
                <div className="col-span-2 panel space-y-6">
                  <h3 className="panel-title">Chaîne de Causalité & Preuves</h3>
                  
                  <div className="bg-gray-50 border border-border rounded-xl p-5">
                    <h4 className="text-[10px] font-bold text-text-muted uppercase mb-3">Preuves d'activité suspecte</h4>
                    <ul className="space-y-2 text-xs font-mono text-brand-danger font-medium">
                      {(selectedAlert.reasons || []).map((r, i) => (
                        <li key={i}>✓ {r}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="border border-border rounded-xl p-5">
                    <h4 className="text-[10px] font-bold text-text-muted uppercase mb-4">Arbre de Processus (Sysmon Event 1)</h4>
                    <div className="space-y-3 font-mono text-xs">
                      <div className="p-3 bg-gray-50 border border-border rounded-lg flex justify-between">
                        <span>{selectedAlert.parent}</span>
                        <span className="text-text-muted">Parent PID: {selectedAlert.parent_pid}</span>
                      </div>
                      <div className="text-center text-text-muted font-bold text-sm">↓</div>
                      <div className="p-3 bg-brand-dangerGlow border border-brand-danger text-brand-danger rounded-lg flex justify-between">
                        <span>{selectedAlert.process} (Top Suspect)</span>
                        <span>PID: {selectedAlert.pid}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="panel space-y-6">
                  <h3 className="panel-title">Riposte Active</h3>
                  <div className="border border-border rounded-xl p-5 text-center">
                    <div className="text-[10px] font-bold text-text-muted uppercase mb-2">Décision EDR</div>
                    <div className="text-2xl font-bold text-brand-danger">KILL ORDRE EXÉCUTÉ</div>
                    <div className="text-[10px] text-text-muted mt-2">Terminated automatically via PowerShell agent.</div>
                  </div>
                  <button onClick={() => triggerKill(selectedAlert.pid)} className="btn btn-danger w-full">Forcer un second KILL</button>
                </div>
              </div>
            ) : (
              <div className="panel text-center text-text-muted py-12">Aucune alerte sélectionnée.</div>
            )}
          </div>
        )}

        {/* ====================================================================
            TAB: REPORTS
           ==================================================================== */}
        {activeTab === 'reports' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-1 space-y-3">
              {alerts.map((a, i) => (
                <button
                  key={i}
                  onClick={() => setSelectedReport(a.kill_payload)}
                  className={`w-full p-4 rounded-xl border text-left transition-all ${
                    selectedReport === a.kill_payload ? 'border-brand-primary bg-brand-primaryGlow' : 'border-border bg-white'
                  }`}
                >
                  <div className="font-semibold text-xs truncate">{a.timestamp || 'now'}_powershell.json</div>
                  <div className="text-[10px] text-text-muted mt-1">Diagnostic Forensics</div>
                </button>
              ))}
            </div>
            
            <div className="col-span-2 panel">
              <h3 className="panel-title mb-6">Archive Diagnostique JSON</h3>
              {selectedReport ? (
                <pre className="bg-gray-50 border border-border rounded-xl p-6 font-mono text-[10px] text-slate-800 overflow-auto max-h-[450px]">
                  {JSON.stringify(selectedReport, null, 2)}
                </pre>
              ) : (
                <div className="text-center text-text-muted py-12">Sélectionnez un rapport d'incident.</div>
              )}
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: RESPONSE LOGS
           ==================================================================== */}
        {activeTab === 'response_logs' && (
          <div className="panel">
            <h3 className="panel-title mb-6">Historique des Actions Correctives</h3>
            <div className="table-container">
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Horodatage</th>
                    <th>Action</th>
                    <th>Cible</th>
                    <th>PID</th>
                    <th>Statut</th>
                    <th>Canal</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((a, i) => (
                    <tr key={i}>
                      <td>{a.timestamp || 'Aujourd\'hui'}</td>
                      <td><span className="badge badge-danger">KILL PROCESS</span></td>
                      <td>{a.kill_payload?.process}</td>
                      <td><span className="code-text">{a.kill_payload?.pid}</span></td>
                      <td><span className="badge badge-success">SUCCESS</span></td>
                      <td>PowerShell Agent</td>
                    </tr>
                  ))}
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan="6" className="text-center text-text-muted py-6">Aucune action corrective enregistrée.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: ML INSIGHTS
           ==================================================================== */}
        {activeTab === 'ml_insights' && (
          <div className="grid grid-cols-2 gap-6">
            <div className="panel">
              <h3 className="panel-title mb-6">Poids discriminants du modèle (Feature Importance)</h3>
              <div className="space-y-4">
                {[
                  { name: 'entropy_filenames', pct: 35.4 },
                  { name: 'nb_files_created', pct: 25.2 },
                  { name: 'nb_external_connections', pct: 15.1 },
                  { name: 'nb_files_deleted', pct: 10.2 },
                  { name: 'nb_child_processes', pct: 8.1 },
                ].map((f, i) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs font-medium">
                      <span>{f.name}</span>
                      <span>{f.pct}%</span>
                    </div>
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden border border-border">
                      <div className="h-full bg-brand-primary" style={{ width: `${f.pct}%` }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <h3 className="panel-title mb-6">Métriques du Modèle Random Forest</h3>
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Métrique</th>
                    <th>Valeur</th>
                    <th>Statut</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Précision (Precision)</td>
                    <td>100%</td>
                    <td><span className="badge badge-success">Optimal</span></td>
                  </tr>
                  <tr>
                    <td>Rappel (Recall)</td>
                    <td>100%</td>
                    <td><span className="badge badge-success">Optimal</span></td>
                  </tr>
                  <tr>
                    <td>F1-Score</td>
                    <td>1.00</td>
                    <td><span className="badge badge-success">Optimal</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: RULES CONFIG
           ==================================================================== */}
        {activeTab === 'rules_config' && (
          <div className="panel">
            <h3 className="panel-title mb-6">Coefficients et Poids des Règles Heuristiques</h3>
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Règle Sysmon</th>
                  <th>Événement Déclencheur</th>
                  <th>Poids Attribué</th>
                  <th>Impact Score</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Création massive de fichiers</td>
                  <td>Event ID 11 (&gt; 250 fichiers en 10s)</td>
                  <td><strong>+30 points</strong></td>
                  <td><span className="badge badge-danger">Élevé</span></td>
                </tr>
                <tr>
                  <td>Entropie anormale des noms</td>
                  <td>Calcul d'entropie de Shannon (&gt; 5.0)</td>
                  <td><strong>+40 points</strong></td>
                  <td><span className="badge badge-danger">Critique</span></td>
                </tr>
                <tr>
                  <td>Processus enfant suspect</td>
                  <td>Event ID 1 (vssadmin, cmd, powershell)</td>
                  <td><strong>+20 points</strong></td>
                  <td><span className="badge badge-warning">Moyen</span></td>
                </tr>
                <tr>
                  <td>Connexion réseau externe</td>
                  <td>Event ID 3 (IP publique destination)</td>
                  <td><strong>+10 points</strong></td>
                  <td><span className="badge badge-success">Faible</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* ====================================================================
            TAB: SANDBOX
           ==================================================================== */}
        {activeTab === 'sandbox' && (
          <div className="panel max-w-xl">
            <h3 className="panel-title mb-6">Soumettre un fichier pour diagnostic</h3>
            <div className="space-y-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-bold text-text-muted uppercase">Chemin ou nom du fichier</label>
                <input 
                  type="text" 
                  value={sandboxFile} 
                  onChange={(e) => setSandboxFile(e.target.value)}
                  placeholder="Ex: C:\Users\franc\Desktop\agent\suspect.exe"
                  className="border border-border rounded-lg p-2.5 text-xs bg-white"
                />
              </div>
              <button 
                onClick={handleRunSandbox} 
                className="btn btn-primary"
                disabled={sandboxLoading}
              >
                {sandboxLoading ? 'Analyse en cours...' : 'Lancer l\'analyse comportementale'}
              </button>

              {sandboxResult && (
                <div className="mt-6 border border-border rounded-xl p-5 bg-gray-50 space-y-3 text-xs">
                  <div><strong>Entropie calculée :</strong> {sandboxResult.entropy}</div>
                  <div><strong>Score de suspicion :</strong> {sandboxResult.score}/100</div>
                  <div><strong>Verdict :</strong> <span className={sandboxResult.score > 50 ? 'text-brand-danger font-bold' : 'text-brand-success font-bold'}>{sandboxResult.decision}</span></div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: EXCLUSIONS
           ==================================================================== */}
        {activeTab === 'exclusions' && (
          <div className="space-y-6">
            <div className="panel max-w-xl">
              <h3 className="panel-title mb-6">Ajouter une exclusion</h3>
              <div className="grid grid-cols-3 gap-4">
                <select 
                  value={newExclusionType} 
                  onChange={(e) => setNewExclusionType(e.target.value)}
                  className="border border-border rounded-lg p-2 text-xs bg-white"
                >
                  <option value="Folder">Dossier</option>
                  <option value="Process">Processus</option>
                </select>
                <input 
                  type="text" 
                  value={newExclusionPath} 
                  onChange={(e) => setNewExclusionPath(e.target.value)}
                  placeholder="Chemin complet"
                  className="col-span-2 border border-border rounded-lg p-2 text-xs bg-white"
                />
              </div>
              <button 
                onClick={() => {
                  if(!newExclusionPath) return;
                  setExclusions([...exclusions, { id: exclusions.length + 1, type: newExclusionType, path: newExclusionPath, comment: "Exclusion manuelle" }]);
                  setNewExclusionPath("");
                }} 
                className="btn btn-primary mt-4"
              >
                Ajouter l'exclusion
              </button>
            </div>

            <div className="panel">
              <h3 className="panel-title mb-6">Exclusions actives</h3>
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Chemin</th>
                    <th>Commentaire</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {exclusions.map((e) => (
                    <tr key={e.id}>
                      <td><span className="badge badge-warning">{e.type}</span></td>
                      <td className="font-mono text-xs">{e.path}</td>
                      <td>{e.comment}</td>
                      <td>
                        <button 
                          onClick={() => setExclusions(exclusions.filter(item => item.id !== e.id))}
                          className="text-brand-danger hover:underline font-semibold"
                        >
                          Retirer
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: AUDIT LOGS
           ==================================================================== */}
        {activeTab === 'audit_logs' && (
          <div className="panel">
            <h3 className="panel-title mb-6">Journal d'Audit de la Console SOC</h3>
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Horodatage</th>
                  <th>Utilisateur</th>
                  <th>Action</th>
                  <th>Détails</th>
                  <th>IP Source</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Aujourd'hui, 15:47:12</td>
                  <td>Administrateur SOC (N3)</td>
                  <td>Exclusion créée</td>
                  <td>Ajout d'une exclusion sur C:\Windows\System32\svchost.exe</td>
                  <td>192.168.10.2</td>
                </tr>
                <tr>
                  <td>Aujourd'hui, 14:42:01</td>
                  <td>Ransomware Detector Engine</td>
                  <td>Active Response (KILL)</td>
                  <td>Processus powershell.exe (PID 6128) exterminé automatiquement</td>
                  <td>localhost</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* ====================================================================
            TAB: TEAM
           ==================================================================== */}
        {activeTab === 'team' && (
          <div className="panel">
            <h3 className="panel-title mb-6">Membres de l'Équipe de Réponse</h3>
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Nom</th>
                  <th>Rôle</th>
                  <th>Permissions</th>
                  <th>Dernière connexion</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Franck</strong></td>
                  <td><span className="badge badge-danger">SOC Manager (N3)</span></td>
                  <td>Contrôle total, Isolation, Exclusions</td>
                  <td>Aujourd'hui, 14:02:11</td>
                </tr>
                <tr>
                  <td><strong>Pipeline Connector Agent</strong></td>
                  <td><span className="badge badge-success">Automated Agent</span></td>
                  <td>Lecture télémétrie, Envoi KILL</td>
                  <td>En ligne</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}

        {/* ====================================================================
            TAB: SETTINGS
           ==================================================================== */}
        {activeTab === 'settings' && (
          <div className="grid grid-cols-2 gap-6">
            <div className="panel">
              <h3 className="panel-title mb-6">Moteurs de détection actifs</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center pb-3 border-b border-border">
                  <div>
                    <h4 className="font-semibold text-xs">Moteur de Règles (Rules Engine)</h4>
                    <p className="text-[10px] text-text-muted">Calcul basé sur les déviations statistiques (Z-score)</p>
                  </div>
                  <input type="checkbox" defaultChecked className="w-4 h-4" />
                </div>
                <div className="flex justify-between items-center">
                  <div>
                    <h4 className="font-semibold text-xs">Random Forest Model (Machine Learning)</h4>
                    <p className="text-[10px] text-text-muted">Inférence par forêt d'arbres décisionnels pré-entraînés</p>
                  </div>
                  <input type="checkbox" defaultChecked className="w-4 h-4" />
                </div>
              </div>
            </div>

            <div className="panel">
              <h3 className="panel-title mb-6">Seuils et Réglages Généraux</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-bold text-text-muted uppercase">Seuil d'Alerte Heuristique</label>
                  <input type="number" defaultValue="0.70" step="0.05" className="border border-border rounded-lg p-2 text-xs bg-white" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-bold text-text-muted uppercase">Seuil de KILL automatique</label>
                  <input type="number" defaultValue="80" step="5" className="border border-border rounded-lg p-2 text-xs bg-white" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-bold text-text-muted uppercase">Intervalle de Polling Agent (s)</label>
                  <input type="number" defaultValue="2" className="border border-border rounded-lg p-2 text-xs bg-white" />
                </div>
                <div className="flex flex-col gap-1">
                  <label className="text-[9px] font-bold text-text-muted uppercase">Fenêtre d'agrégation (s)</label>
                  <input type="number" defaultValue="10" className="border border-border rounded-lg p-2 text-xs bg-white" />
                </div>
              </div>
              <button onClick={() => alert('Configuration sauvegardée')} className="btn btn-primary w-full mt-6">Sauvegarder</button>
            </div>
          </div>
        )}

        {/* ====================================================================
            TAB: DOCS / RUNBOOKS
           ==================================================================== */}
        {activeTab === 'docs' && (
          <div className="panel space-y-6">
            <h3 className="panel-title">EDR SOC Runbooks & Aide</h3>
            
            <div className="space-y-4">
              <div className="border border-border rounded-lg p-5">
                <h4 className="font-bold text-sm mb-2">Procédure de Réponse à un Ransomware (Runbook A-1)</h4>
                <p className="text-xs text-text-muted leading-relaxed">
                  Dès qu'une alerte Ransomware critique est levée (Score ≥ 80), le Cerveau EDR calcule le PID suspect le plus actif. 
                  L'Agent PowerShell déployé applique immédiatement une frappe chirurgicale en stoppant le PID. 
                  Si le malware continue d'écrire des fichiers à forte entropie, l'analyste SOC doit cliquer sur le bouton **Isoler la machine** 
                  dans l'onglet **Terminaux** pour neutraliser tout mouvement latéral ou exfiltration de données.
                </p>
              </div>

              <div className="border border-border rounded-lg p-5">
                <h4 className="font-bold text-sm mb-2">Signification des Features Comportementales</h4>
                <p className="text-xs text-text-muted leading-relaxed">
                  L'EDR surveille 12 features système fondamentales. Les plus importantes pour le Ransomware sont l'entropie de Shannon
                  des noms de fichiers (détecte les extensions chiffrées/aléatoires) et le nombre de créations de fichiers (Event ID 11).
                </p>
              </div>
            </div>
          </div>
        )}

      </main>
    </div>
  );
}
