import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { healthApi } from '../lib/api';
import {
  LayoutDashboard,
  Radar,
  PlusCircle,
  Settings,
  Server,
  ExternalLink,
  ChevronDown,
  Briefcase,
  Bot,
  BookOpen,
  Menu,
  LogOut,
  Users,
  User,
  Shield,
  KeyRound,
  Fingerprint,
  Sparkles,
  Lock,
  Sun,
  Moon,
  Monitor,
  Cpu,
  Calendar,
  ChevronRight,
} from 'lucide-react';
import { clsx } from 'clsx';
import { ModalShell } from './ui';
import { useAuthStore } from '../lib/auth';
import { useTheme, type Theme } from '../lib/theme';
import { NotificationBell, NotificationPanel } from './NotificationCenter';
import { CommandPalette, CommandPaletteTrigger } from './CommandPalette';

interface NavItem {
  name: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  /** Only shown when the user holds this permission. */
  permission?: string;
  /** Only shown when signed in. */
  authOnly?: boolean;
}

interface NavGroup {
  id: string;
  /** Heading text; null renders the items with no heading. */
  label: string | null;
  items: NavItem[];
}

/* Grouped navigation. Order is the order of the workflow: look, investigate,
   work with what was found, configure, administer. */
const NAV_GROUPS: NavGroup[] = [
  {
    id: 'overview',
    label: null,
    items: [{ name: 'Dashboard', to: '/', icon: LayoutDashboard }],
  },
  {
    id: 'investigate',
    label: 'Investigate',
    items: [
      { name: 'New Scan', to: '/scans/new', icon: PlusCircle },
      { name: 'Scans', to: '/scans', icon: Radar },
      { name: 'Schedules', to: '/schedules', icon: Calendar },
      { name: 'Workspaces', to: '/workspaces', icon: Briefcase },
    ],
  },
  {
    id: 'intelligence',
    label: 'Intelligence',
    items: [
      { name: 'Modules', to: '/modules', icon: Cpu },
      { name: 'Agents', to: '/agents', icon: Bot },
    ],
  },
  {
    id: 'configure',
    label: 'Configure',
    items: [
      { name: 'Settings', to: '/settings', icon: Settings },
      { name: 'Data Source Credentials', to: '/credentials', icon: KeyRound },
      { name: 'AI Connections', to: '/ai-connections', icon: Sparkles },
      // SpiderFoot's own REST tokens, not the third-party module keys above.
      { name: 'Access Tokens', to: '/api-keys', icon: Fingerprint, authOnly: true },
    ],
  },
  {
    id: 'administration',
    label: 'Administration',
    items: [
      { name: 'Users', to: '/users', icon: Users, permission: 'user:read' },
      { name: 'SSO Settings', to: '/sso-settings', icon: Lock, permission: 'config:write' },
    ],
  },
  {
    id: 'help',
    label: 'Help',
    items: [{ name: 'Documentation', to: '/documentation', icon: BookOpen }],
  },
];

const NAV_COLLAPSED_KEY = 'sf-nav-collapsed';

function loadCollapsed(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem(NAV_COLLAPSED_KEY) || '{}') as Record<string, boolean>;
  } catch {
    return {};
  }
}

function navLinkClass({ isActive }: { isActive: boolean }): string {
  return clsx(
    'flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-colors',
    isActive
      ? 'bg-spider-600/20 text-spider-400'
      : 'text-dark-300 hover:bg-dark-800 hover:text-dark-100',
  );
}

interface ServiceLink {
  name: string;
  url: string;
  internal: boolean;
  desc: string;
  /** Key in health.components from /health/dashboard — shows a live status dot when set */
  healthKey?: string;
}

const SERVICE_LINKS: ServiceLink[] = [
  { name: 'AI Agents',  url: '/agents',       internal: true,  desc: 'AI agent management'                     },
  { name: 'Grafana',    url: '/grafana/',      internal: false, desc: 'Metrics & dashboards'                    },
  { name: 'Jaeger',     url: '/jaeger/',       internal: false, desc: 'Distributed tracing'                     },
  { name: 'Prometheus', url: '/prometheus/',   internal: false, desc: 'Metrics collection'                      },
  { name: 'Traefik',    url: '/dashboard/',    internal: false, desc: 'Reverse proxy'                           },
  { name: 'MinIO',      url: '/minio/',        internal: false, desc: 'Object storage',  healthKey: 'minio'    },
  { name: 'Flower',     url: '/flower/',       internal: false, desc: 'Celery monitor'                          },
  { name: 'Vector',     url: '/health/vector', internal: false, desc: 'Data pipeline',   healthKey: 'vector'   },
];

const APP_VERSION = '6.0.1';

export default function Layout() {
  const [showAbout, setShowAbout] = useState(false);
  const [servicesOpen, setServicesOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(loadCollapsed);
  const location = useLocation();
  const { user, isAuthenticated, logout, hasPermission } = useAuthStore();

  const toggleGroup = (id: string) => {
    setCollapsed((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      try { localStorage.setItem(NAV_COLLAPSED_KEY, JSON.stringify(next)); } catch { /* storage unavailable */ }
      return next;
    });
  };

  const itemVisible = (item: NavItem): boolean => {
    if (item.permission) return isAuthenticated && hasPermission(item.permission);
    if (item.authOnly) return isAuthenticated;
    return true;
  };

  const isItemActive = (item: NavItem): boolean =>
    item.to === '/' ? location.pathname === '/' : location.pathname === item.to || location.pathname.startsWith(item.to + '/');
  const { theme, setTheme } = useTheme();

  // Poll health dashboard so the services dropdown can show live status dots.
  // Shares the same query key as Dashboard.tsx — no extra network requests when both are mounted.
  const { data: healthData } = useQuery({
    queryKey: ['health-dashboard'],
    queryFn: ({ signal }) => healthApi.dashboard(signal),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const themeOptions: { key: Theme; icon: typeof Sun; label: string }[] = [
    { key: 'light', icon: Sun, label: 'Light' },
    { key: 'dark', icon: Moon, label: 'Dark' },
    { key: 'system', icon: Monitor, label: 'System' },
  ];

  return (
    <div className="flex h-full">
      {/* Skip to content — WCAG 2.4.1 */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2 focus:bg-spider-600 focus:text-white focus:rounded-lg focus:text-sm focus:font-medium"
      >
        Skip to content
      </a>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={clsx(
        'fixed lg:relative z-40 w-64 bg-dark-900 border-r border-dark-700 flex flex-col h-full transition-transform lg:translate-x-0',
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      )}>
        {/* Logo */}
        <div
          className="flex items-center gap-3 px-6 py-5 border-b border-dark-700 cursor-pointer hover:bg-dark-800/50 transition-colors"
          onClick={() => setShowAbout(true)}
        >
          <img src="/spiderfoot-icon.png" alt="SpiderFoot" className="h-8 w-8" />
          <div>
            <h1 className="text-lg font-bold text-foreground">SpiderFoot</h1>
            <p className="text-xs text-dark-400">OSINT Platform</p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-3 overflow-y-auto" aria-label="Main navigation">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter(itemVisible);
            if (items.length === 0) return null;
            // A collapsed group stays open while it holds the page being viewed.
            const open = !group.label || !collapsed[group.id] || items.some(isItemActive);
            return (
              <div key={group.id} className="mb-2">
                {group.label && (
                  <button
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    aria-expanded={open}
                    className="w-full flex items-center gap-1.5 px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-dark-500 hover:text-dark-300 transition-colors"
                  >
                    <ChevronRight className={clsx('h-3 w-3 transition-transform', open && 'rotate-90')} />
                    {group.label}
                  </button>
                )}
                {open && (
                  <div className="space-y-0.5">
                    {items.map((item) => (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        end={item.to === '/'}
                        onClick={() => { if (window.innerWidth < 1024) setSidebarOpen(false); }}
                        className={navLinkClass}
                      >
                        <item.icon className="h-4 w-4 flex-shrink-0" />
                        {item.name}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* Theme toggle */}
        <div className="px-3 pb-2 border-t border-dark-700">
          <div className="flex items-center gap-1 p-1 mt-2 bg-dark-800/60 rounded-lg">
            {themeOptions.map((opt) => (
              <button
                key={opt.key}
                onClick={() => setTheme(opt.key)}
                className={clsx(
                  'flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs font-medium rounded-md transition-all duration-200',
                  theme === opt.key
                    ? 'bg-spider-600/20 text-spider-400 shadow-sm'
                    : 'text-dark-400 hover:text-dark-200 hover:bg-dark-700/50',
                )}
                title={opt.label}
              >
                <opt.icon className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">{opt.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Quick search */}
        <div className="px-3 pb-1">
          <CommandPaletteTrigger />
        </div>

        {/* Notification center */}
        <div className="px-3 pb-1 relative">
          <div className="flex items-center gap-2 px-3">
            <NotificationBell />
            <span className="text-xs text-dark-500">Notifications</span>
          </div>
          <NotificationPanel />
        </div>

        {/* Services dropdown */}
        <div className="px-3 pb-2">
          <button
            onClick={() => setServicesOpen(!servicesOpen)}
            className="w-full flex items-center gap-2 px-3 py-2 text-xs text-dark-400 hover:text-dark-200 hover:bg-dark-800 rounded-lg transition-colors"
          >
            <Server className="h-3.5 w-3.5" />
            <span className="flex-1 text-left">Services</span>
            <ChevronDown className={clsx('h-3 w-3 transition-transform', servicesOpen && 'rotate-180')} />
          </button>
          {servicesOpen && (
            <div className="mt-1 space-y-0.5 animate-fade-in">
              {SERVICE_LINKS.map((svc) =>
                svc.internal ? (
                  <NavLink
                    key={svc.name}
                    to={svc.url}
                    className="flex items-center gap-2 px-3 py-1.5 text-xs text-dark-400 hover:text-dark-200 hover:bg-dark-800 rounded-lg transition-colors"
                  >
                    <Bot className="h-3 w-3" />
                    <span className="flex-1">{svc.name}</span>
                  </NavLink>
                ) : (
                  <a
                    key={svc.name}
                    href={svc.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={`${svc.desc}${svc.healthKey ? ` — ${(healthData as any)?.components?.[svc.healthKey]?.status ?? 'unknown'}` : ''}`}
                    className="flex items-center gap-2 px-3 py-1.5 text-xs text-dark-400 hover:text-dark-200 hover:bg-dark-800 rounded-lg transition-colors"
                  >
                    <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    <span className="flex-1">{svc.name}</span>
                    {svc.healthKey && (
                      <span
                        className={clsx(
                          'h-1.5 w-1.5 rounded-full flex-shrink-0',
                          (healthData as any)?.components?.[svc.healthKey]?.status === 'up'       && 'bg-green-400',
                          (healthData as any)?.components?.[svc.healthKey]?.status === 'degraded' && 'bg-yellow-400',
                          (healthData as any)?.components?.[svc.healthKey]?.status === 'down'     && 'bg-red-400',
                          !(healthData as any)?.components?.[svc.healthKey]?.status              && 'bg-dark-500',
                        )}
                      />
                    )}
                  </a>
                ),
              )}
            </div>
          )}
        </div>

        {/* User menu & Footer */}
        <div className="px-3 pb-2 border-t border-dark-700">
          {isAuthenticated && user ? (
            <div className="py-3">
              <div className="flex items-center gap-3 px-3 py-2">
                <div className="h-8 w-8 rounded-full bg-spider-600/20 flex items-center justify-center flex-shrink-0">
                  <User className="h-4 w-4 text-spider-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{user.username}</p>
                  <div className="flex items-center gap-1">
                    <Shield className="h-3 w-3 text-dark-500" />
                    <p className="text-xs text-dark-500 capitalize">{user.role}</p>
                  </div>
                </div>
              </div>
              <button
                onClick={() => logout()}
                className="w-full flex items-center gap-2 px-3 py-2 mt-1 text-xs text-dark-400 hover:text-red-400 hover:bg-dark-800 rounded-lg transition-colors"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign out
              </button>
            </div>
          ) : null}
          <div className="px-3 py-2">
            <p className="text-xs text-dark-500">SpiderFoot v{APP_VERSION}</p>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {/* Mobile header */}
        <div className="lg:hidden flex items-center gap-3 px-4 py-3 border-b border-dark-700 bg-dark-900">
          <button onClick={() => setSidebarOpen(!sidebarOpen)} aria-label="Toggle navigation menu" className="text-dark-300 hover:text-foreground">
            <Menu className="h-5 w-5" />
          </button>
          <img src="/spiderfoot-icon.png" alt="SpiderFoot" className="h-5 w-5" />
          <span className="text-sm font-bold text-foreground">SpiderFoot</span>
        </div>
        <div id="main-content" className="px-6 py-8">
          <Outlet />
        </div>
      </main>

      {/* About Modal */}
      {showAbout && (
        <ModalShell title="About SpiderFoot" onClose={() => setShowAbout(false)}>
          <div className="text-center">
            <img src="/spiderfoot-header-dark.png" alt="SpiderFoot" className="h-16 mx-auto mb-4" />
            <p className="text-dark-400 text-sm mt-1">Open Source Intelligence Automation</p>
            <p className="text-spider-400 font-mono text-sm mt-3">v{APP_VERSION}</p>
            <div className="mt-6 space-y-2 text-sm text-dark-400">
              <p>An OSINT automation tool for reconnaissance.</p>
              <p>
                <a
                  href="https://github.com/poppopjmp/spiderfoot"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-spider-400 hover:text-spider-300 underline decoration-spider-600/50 underline-offset-2"
                >
                  View on GitHub
                </a>
              </p>
            </div>
          </div>
        </ModalShell>
      )}

      {/* Command Palette (⌘K / Ctrl+K) */}
      <CommandPalette />
    </div>
  );
}
