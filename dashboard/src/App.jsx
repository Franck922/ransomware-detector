/**
 * Racine de la console SOC.
 *
 * L'ancien App.jsx faisait 1608 lignes et concentrait la navigation, les appels
 * réseau, l'authentification et le rendu de treize onglets. Il est désormais
 * réduit à l'assemblage : authentification, canal temps réel, routage.
 */

import { useCallback, useEffect, useState } from 'react';
import { AuthProvider, useAuth } from './auth/AuthContext';
import LoginScreen from './auth/LoginScreen';
import PasswordRotationScreen from './auth/PasswordRotationScreen';
import { RealtimeProvider } from './realtime/RealtimeProvider';
import Layout from './components/Layout';
import { Spinner, Toast } from './components/ui';
import { useResource } from './hooks/useResource';
import { alerts as alertsApi } from './api/endpoints';

import Overview from './pages/Overview';
import Machines from './pages/Machines';
import MachineDetail from './pages/MachineDetail';
import Alerts from './pages/Alerts';
import AlertDetail from './pages/AlertDetail';
import Responses from './pages/Responses';
import MlInsights from './pages/MlInsights';
import Rules from './pages/Rules';
import Exclusions from './pages/Exclusions';
import AuditLogs from './pages/AuditLogs';
import Team from './pages/Team';
import SettingsPage from './pages/Settings';
import Docs from './pages/Docs';

function Console() {
  const [tab, setTab] = useState('overview');
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [selectedMachineId, setSelectedMachineId] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = useCallback((next) => setToast(next), []);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(timer);
  }, [toast]);

  // Compteur du badge de navigation : seules les alertes non traitées comptent.
  const openAlerts = useResource(
    (signal) => alertsApi.list({ open_only: true, limit: 1 }, signal),
    { channels: ['alerts'] },
  );

  const openAlert = useCallback((alertId) => {
    setSelectedAlertId(alertId);
    setTab('alert_detail');
  }, []);

  const openMachine = useCallback((machineId) => {
    setSelectedMachineId(machineId);
    setTab('machine_detail');
  }, []);

  const navigate = useCallback((next) => {
    setTab(next);
    if (next !== 'alert_detail') setSelectedAlertId(null);
    if (next !== 'machine_detail') setSelectedMachineId(null);
  }, []);

  const pages = {
    overview: <Overview onOpenAlert={openAlert} />,
    machines: <Machines onOpenMachine={openMachine} />,
    machine_detail: (
      <MachineDetail
        machineId={selectedMachineId}
        onBack={() => navigate('machines')}
        onOpenAlert={openAlert}
        onToast={showToast}
      />
    ),
    alerts: <Alerts onOpenAlert={openAlert} />,
    alert_detail: (
      <AlertDetail
        alertId={selectedAlertId}
        onBack={() => navigate('alerts')}
        onToast={showToast}
      />
    ),
    responses: <Responses />,
    ml: <MlInsights />,
    rules: <Rules />,
    exclusions: <Exclusions onToast={showToast} />,
    audit: <AuditLogs />,
    team: <Team onToast={showToast} />,
    settings: <SettingsPage onToast={showToast} />,
    docs: <Docs />,
  };

  return (
    <>
      <Layout
        activeTab={tab}
        onNavigate={navigate}
        openAlertCount={openAlerts.data?.total || 0}
      >
        {pages[tab] || pages.overview}
      </Layout>
      <Toast toast={toast} onClose={() => setToast(null)} />
    </>
  );
}

function Gate() {
  const { checking, isAuthenticated, mustChangePassword } = useAuth();

  if (checking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-bg-main">
        <Spinner label="Vérification de la session…" />
      </div>
    );
  }

  if (!isAuthenticated) return <LoginScreen />;
  if (mustChangePassword) return <PasswordRotationScreen />;

  // Le canal temps réel n'est ouvert qu'une fois la session pleinement valide :
  // il s'authentifie avec le même cookie que l'API.
  return (
    <RealtimeProvider enabled>
      <Console />
    </RealtimeProvider>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  );
}
