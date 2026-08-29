/** Coquille de l'application : navigation latérale (drawer mobile), en-tête, temps réel. */

import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle,
  FileCheck,
  HelpCircle,
  List,
  LogOut,
  Menu,
  RefreshCw,
  Settings as SettingsIcon,
  ShieldAlert,
  Terminal,
  Users,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { useRealtime } from '../realtime/RealtimeProvider';
import { RoleBadge, formatRelative } from './ui';

export const NAV_SECTIONS = [
  {
    label: 'Surveillance',
    items: [
      { id: 'overview', label: 'Dashboard', icon: Activity },
      { id: 'machines', label: 'Terminaux', icon: Terminal, aliases: ['machine_detail'] },
    ],
  },
  {
    label: 'Réponse aux incidents',
    items: [
      {
        id: 'alerts',
        label: 'Alertes de sécurité',
        icon: AlertTriangle,
        aliases: ['alert_detail'],
        badge: 'alerts',
      },
      { id: 'responses', label: 'Journal des réponses', icon: ShieldAlert },
    ],
  },
  {
    label: 'Analyse & moteurs',
    items: [
      { id: 'ml', label: 'Statistiques ML', icon: Brain },
      { id: 'rules', label: 'Moteur heuristique', icon: List },
    ],
  },
  {
    label: 'Configuration & outils',
    items: [
      { id: 'exclusions', label: "Règles d'exclusion", icon: CheckCircle },
      { id: 'audit', label: "Journal d'audit", icon: FileCheck },
      { id: 'team', label: 'Équipe SOC', icon: Users, minRole: 'N3' },
      { id: 'settings', label: 'Configuration', icon: SettingsIcon },
      { id: 'docs', label: 'Documentation', icon: HelpCircle },
    ],
  },
];

export const PAGE_META = {
  overview: {
    title: "Vue d'ensemble du SOC",
    subtitle: 'Indicateurs de compromission et activité du parc surveillé',
  },
  machines: {
    title: 'Terminaux surveillés',
    subtitle: "Postes Windows remontant des événements Sysmon à l'API",
  },
  machine_detail: {
    title: 'Détail du terminal',
    subtitle: 'Activité observée, alertes et réponses actives sur ce poste',
  },
  alerts: {
    title: 'Journal des alertes',
    subtitle: 'Anomalies détectées par le moteur heuristique et le modèle ML',
  },
  alert_detail: {
    title: "Analyse forensics de l'alerte",
    subtitle: 'Processus suspect, causalité et justification du score',
  },
  responses: {
    title: 'Journal des réponses actives',
    subtitle: 'Arrêts de processus et isolations réseau, automatiques ou déclenchés',
  },
  ml: {
    title: 'Statistiques du moteur ML',
    subtitle: 'Caractéristiques du modèle chargé et importance réelle des features',
  },
  rules: {
    title: 'Moteur heuristique',
    subtitle: 'Règles comportementales appliquées à chaque fenêtre de 10 secondes',
  },
  exclusions: {
    title: "Règles d'exclusion",
    subtitle: 'Chemins et processus retirés du périmètre de détection',
  },
  audit: {
    title: "Journal d'audit",
    subtitle: 'Traçabilité des actions analystes et des réponses automatiques',
  },
  team: { title: 'Équipe SOC', subtitle: 'Comptes analystes et niveaux de privilège' },
  settings: { title: 'Configuration système', subtitle: 'Paramètres de détection et de rétention' },
  docs: { title: 'Documentation', subtitle: 'Architecture, procédures et référence des API' },
};

function RealtimeIndicator({ compact = false }) {
  const { connected, lastEventAt } = useRealtime();
  const [, forceRender] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => forceRender((value) => value + 1), 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="flex items-center gap-2 text-[10px] font-medium">
      {connected ? (
        <>
          <Wifi className="w-3.5 h-3.5 text-brand-success shrink-0" />
          {!compact ? (
            <span className="text-text-muted hidden sm:inline">
              Temps réel actif
              {lastEventAt ? ` · maj ${formatRelative(lastEventAt)}` : ''}
            </span>
          ) : null}
          {compact ? <span className="text-text-muted sm:hidden">Live</span> : null}
        </>
      ) : (
        <>
          <WifiOff className="w-3.5 h-3.5 text-brand-warning shrink-0" />
          <span className="text-brand-warning hidden md:inline">
            Mode dégradé (rafraîchissement périodique)
          </span>
          <span className="text-brand-warning md:hidden">Dégradé</span>
        </>
      )}
    </div>
  );
}

function SidebarNav({ activeTab, onNavigate, openAlertCount, hasRole, onNavigateItem }) {
  return (
    <nav className="flex-1 px-4 space-y-6 overflow-y-auto">
      {NAV_SECTIONS.map((section) => {
        const visible = section.items.filter(
          (item) => !item.minRole || hasRole(item.minRole),
        );
        if (visible.length === 0) return null;

        return (
          <div key={section.label}>
            <span className="px-4 text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-2">
              {section.label}
            </span>
            <div className="space-y-1">
              {visible.map((item) => {
                const Icon = item.icon;
                const isActive =
                  activeTab === item.id || (item.aliases || []).includes(activeTab);
                const badgeValue = item.badge === 'alerts' ? openAlertCount : 0;

                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      onNavigate(item.id);
                      onNavigateItem?.();
                    }}
                    className={`w-full flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-medium transition-all ${
                      isActive
                        ? 'bg-brand-primaryGlow text-brand-primary font-semibold'
                        : 'text-text-muted hover:bg-gray-50'
                    }`}
                  >
                    <span className="flex items-center gap-3">
                      <Icon className="w-4 h-4 shrink-0" />
                      <span>{item.label}</span>
                    </span>
                    {badgeValue > 0 ? (
                      <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-brand-dangerGlow text-brand-danger">
                        {badgeValue}
                      </span>
                    ) : null}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </nav>
  );
}

export default function Layout({ activeTab, onNavigate, openAlertCount, children }) {
  const { user, logout, hasRole } = useAuth();
  const { refreshAll, connected } = useRealtime();
  const [menuOpen, setMenuOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    if (!menuOpen) return undefined;
    const onClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [menuOpen]);

  // Ferme le drawer à chaque changement d'onglet / redimensionnement desktop.
  useEffect(() => {
    setSidebarOpen(false);
  }, [activeTab]);

  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth >= 1024) setSidebarOpen(false);
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  useEffect(() => {
    if (!sidebarOpen) return undefined;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previous;
    };
  }, [sidebarOpen]);

  const meta = PAGE_META[activeTab] || PAGE_META.overview;

  const renderSidebar = (showClose) => (
    <>
      <div className="p-5 lg:p-6 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 bg-brand-primary rounded flex items-center justify-center font-bold text-white text-sm shrink-0">
            EDR
          </div>
          <span className="font-semibold text-base tracking-tight truncate">SOC Console</span>
        </div>
        {showClose ? (
          <button
            type="button"
            className="btn btn-outline p-2"
            onClick={() => setSidebarOpen(false)}
            aria-label="Fermer le menu"
          >
            <X className="w-4 h-4" />
          </button>
        ) : null}
      </div>

      <SidebarNav
        activeTab={activeTab}
        onNavigate={onNavigate}
        openAlertCount={openAlertCount}
        hasRole={hasRole}
        onNavigateItem={() => setSidebarOpen(false)}
      />

      <div className="p-4 border-t border-border mt-auto">
        <div className="flex items-center gap-2 text-[10px] text-text-muted font-medium">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              connected ? 'bg-brand-success animate-pulse' : 'bg-brand-warning'
            }`}
          />
          <span>{connected ? 'Flux temps réel connecté' : 'Reconnexion en cours…'}</span>
        </div>
      </div>
    </>
  );

  return (
    <div className="flex min-h-screen bg-bg-main text-text-main font-sans antialiased">
      {/* Sidebar desktop */}
      <aside className="hidden lg:flex w-64 bg-bg-sidebar border-r border-border flex-col fixed h-screen z-20 overflow-y-auto">
        {renderSidebar(false)}
      </aside>

      {/* Drawer mobile / tablette */}
      {sidebarOpen ? (
        <div className="lg:hidden fixed inset-0 z-40">
          <button
            type="button"
            className="absolute inset-0 bg-slate-900/40 backdrop-blur-[1px]"
            aria-label="Fermer le menu"
            onClick={() => setSidebarOpen(false)}
          />
          <aside className="relative w-[min(18rem,88vw)] h-full bg-bg-sidebar border-r border-border flex flex-col shadow-2xl animate-[slideIn_0.18s_ease-out]">
            {renderSidebar(true)}
          </aside>
        </div>
      ) : null}

      <main className="w-full lg:ml-64 flex-1 min-h-screen min-w-0">
        <div className="p-4 sm:p-6 lg:p-10">
          <header className="flex flex-col gap-4 sm:flex-row sm:justify-between sm:items-start mb-6 sm:mb-8 border-b border-border pb-4 sm:pb-5">
            <div className="flex items-start gap-3 min-w-0">
              <button
                type="button"
                className="lg:hidden btn btn-outline p-2 shrink-0 mt-0.5"
                onClick={() => setSidebarOpen(true)}
                aria-label="Ouvrir le menu"
              >
                <Menu className="w-4 h-4" />
              </button>
              <div className="min-w-0">
                <h1 className="text-lg sm:text-xl font-bold tracking-tight truncate">
                  {meta.title}
                </h1>
                <p className="text-xs text-text-muted mt-1 leading-relaxed">{meta.subtitle}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 sm:gap-4 shrink-0 flex-wrap justify-end">
              <RealtimeIndicator compact />

              <button
                type="button"
                onClick={refreshAll}
                className="btn btn-outline"
                title="Rafraîchir"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Rafraîchir</span>
              </button>

              <div className="relative" ref={menuRef}>
                <button
                  type="button"
                  onClick={() => setMenuOpen((open) => !open)}
                  className="flex items-center gap-2 sm:gap-3 sm:pl-4 sm:border-l border-border hover:opacity-80 transition-opacity"
                >
                  <div className="w-8 h-8 rounded-full bg-brand-primaryGlow text-brand-primary flex items-center justify-center font-bold text-xs shadow-sm uppercase shrink-0">
                    {user?.email?.[0] || 'U'}
                  </div>
                  <div className="hidden sm:flex flex-col text-left max-w-[10rem]">
                    <span className="text-xs font-bold text-text-main leading-none truncate">
                      {user?.full_name || user?.email}
                    </span>
                    <span className="text-[10px] text-text-muted mt-0.5 truncate">
                      {user?.role_label}
                    </span>
                  </div>
                </button>

                {menuOpen ? (
                  <div className="absolute right-0 mt-3 w-[min(18rem,calc(100vw-2rem))] bg-white border border-border rounded-xl shadow-xl p-4 z-50 text-xs text-left space-y-3">
                    <div className="border-b border-border pb-3">
                      <div className="font-bold text-text-main text-sm break-all">{user?.email}</div>
                      <div className="mt-2">
                        <RoleBadge role={user?.role} />
                      </div>
                    </div>

                    <div>
                      <span className="text-[9px] font-bold text-text-muted uppercase block">
                        Permissions accordées par l'API
                      </span>
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {(user?.permissions || []).map((permission) => (
                          <span
                            key={permission}
                            className="px-1.5 py-0.5 text-[9px] rounded-full bg-brand-primaryGlow text-brand-primary font-medium"
                          >
                            {permission}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="border-t border-border pt-2">
                      <button
                        type="button"
                        onClick={() => {
                          logout();
                          setMenuOpen(false);
                        }}
                        className="w-full text-left py-1.5 px-2.5 hover:bg-red-50 text-brand-danger rounded-lg transition-all flex items-center gap-2 font-semibold"
                      >
                        <LogOut className="w-3.5 h-3.5" />
                        Se déconnecter
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </header>

          {children}
        </div>
      </main>
    </div>
  );
}
