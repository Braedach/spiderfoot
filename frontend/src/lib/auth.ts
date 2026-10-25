/**
 * SpiderFoot Auth Store — Zustand-based authentication state management.
 *
 * Manages JWT tokens, user profile, login/logout, SSO providers,
 * and token refresh lifecycle.
 */
import { create } from 'zustand';
import api from './api';
import { getErrorMessage } from './errors';

// ── Types ────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  role: string;
  display_name: string;
  auth_method: string;
  status: string;
  created_at: number;
  last_login: number;
  sso_provider_id: string;
}

export interface SSOProvider {
  id: string;
  name: string;
  protocol: string;  // oauth2 | saml | ldap
  enabled: boolean;
  default_role: string;
}

export interface AuthStatus {
  auth_required: boolean;
  rbac_enforced: boolean;
  user_count: number;
  sso_providers: SSOProvider[];
  supported_methods: string[];
}

interface AuthState {
  // State
  user: AuthUser | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  authRequired: boolean;
  ssoProviders: SSOProvider[];
  error: string | null;
  // Two independent fetches resolve on mount (auth status, current user) and
  // both set `isLoading`. Track each separately so a permission check can't
  // fire on the gap between the fast one resolving and the slow one still
  // being in flight — see `recomputeLoading`.
  authStatusLoaded: boolean;
  userLoaded: boolean;

  // Actions
  login: (username: string, password: string) => Promise<void>;
  ldapLogin: (providerId: string, username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshAccessToken: () => Promise<boolean>;
  fetchCurrentUser: () => Promise<void>;
  fetchAuthStatus: () => Promise<void>;
  setTokensFromUrl: () => void;
  clearError: () => void;
  hasPermission: (permission: string) => boolean;
}

// ── Permission table (mirrors backend RBAC) ──────────────

const ROLE_PERMISSIONS: Record<string, Set<string>> = {
  viewer: new Set([
    'scan:read', 'report:read', 'data:read', 'engine:read',
    'schedule:read', 'system:health', 'notification:read',
  ]),
  analyst: new Set([
    'scan:read', 'report:read', 'data:read', 'engine:read',
    'schedule:read', 'system:health', 'notification:read',
    'scan:create', 'scan:update', 'scan:abort', 'report:create',
    'data:export', 'schedule:create', 'schedule:update',
    'schedule:trigger', 'config:read', 'ratelimit:read',
  ]),
  operator: new Set([
    'scan:read', 'report:read', 'data:read', 'engine:read',
    'schedule:read', 'system:health', 'notification:read',
    'scan:create', 'scan:update', 'scan:abort', 'report:create',
    'data:export', 'schedule:create', 'schedule:update',
    'schedule:trigger', 'config:read', 'ratelimit:read',
    'scan:delete', 'engine:create', 'engine:update', 'engine:delete',
    'schedule:delete', 'notification:write',
  ]),
  admin: new Set([
    'scan:read', 'report:read', 'data:read', 'engine:read',
    'schedule:read', 'system:health', 'notification:read',
    'scan:create', 'scan:update', 'scan:abort', 'report:create',
    'data:export', 'schedule:create', 'schedule:update',
    'schedule:trigger', 'config:read', 'ratelimit:read',
    'scan:delete', 'engine:create', 'engine:update', 'engine:delete',
    'schedule:delete', 'notification:write',
    'config:write', 'ratelimit:write', 'user:read', 'user:create',
    'user:update', 'user:delete', 'system:admin',
  ]),
};


// ── Token helpers ────────────────────────────────────────

function saveTokens(access: string, refresh: string) {
  try {
    localStorage.setItem('sf_access_token', access);
    localStorage.setItem('sf_refresh_token', refresh);
    // Also set legacy key for backward compat
    localStorage.setItem('sf_api_key', access);
  } catch {
    // QuotaExceeded — tokens are tiny so this is very unlikely
    console.warn('[auth] Failed to save tokens to localStorage');
  }
}

function clearTokens() {
  try {
    localStorage.removeItem('sf_access_token');
    localStorage.removeItem('sf_refresh_token');
    localStorage.removeItem('sf_api_key');
  } catch {
    // Ignore storage errors on clear
  }
}

function loadTokens(): { access: string | null; refresh: string | null } {
  return {
    access: localStorage.getItem('sf_access_token') || localStorage.getItem('sf_api_key'),
    refresh: localStorage.getItem('sf_refresh_token'),
  };
}


// ── Store ────────────────────────────────────────────────

// isLoading stays true until auth status has loaded, and — only when there's
// a token to resolve a user for — the current user has loaded too. A guard
// that gates on `isLoading` must never see it go false while `user` is still
// unresolved; that gap is exactly what let a real admin get redirected away
// from an admin-only page before `fetchCurrentUser` had finished.
function recomputeLoading(authStatusLoaded: boolean, userLoaded: boolean, accessToken: string | null): boolean {
  return !authStatusLoaded || (!!accessToken && !userLoaded);
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  accessToken: loadTokens().access,
  refreshToken: loadTokens().refresh,
  isAuthenticated: !!loadTokens().access,
  isLoading: true,
  authStatusLoaded: false,
  userLoaded: false,
  authRequired: false,
  ssoProviders: [],
  error: null,

  login: async (username: string, password: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.post('/api/auth/login', { username, password });
      const { access_token, refresh_token, user } = res.data;
      saveTokens(access_token, refresh_token);
      set({
        user,
        accessToken: access_token,
        refreshToken: refresh_token,
        isAuthenticated: true,
        isLoading: false,
        authStatusLoaded: true,
        userLoaded: true,
        error: null,
      });
    } catch (err: unknown) {
      const msg = getErrorMessage(err, 'Login failed');
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  ldapLogin: async (providerId: string, username: string, password: string) => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.post('/api/auth/ldap/login', {
        provider_id: providerId,
        username,
        password,
      });
      const { access_token, refresh_token, user } = res.data;
      saveTokens(access_token, refresh_token);
      set({
        user,
        accessToken: access_token,
        refreshToken: refresh_token,
        isAuthenticated: true,
        isLoading: false,
        authStatusLoaded: true,
        userLoaded: true,
        error: null,
      });
    } catch (err: unknown) {
      const msg = getErrorMessage(err, 'LDAP login failed');
      set({ isLoading: false, error: msg });
      throw new Error(msg);
    }
  },

  logout: async () => {
    try {
      await api.post('/api/auth/logout');
    } catch {
      // Ignore — we clear local state regardless
    }
    clearTokens();
    set({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      error: null,
    });
  },

  refreshAccessToken: async () => {
    const { refreshToken } = get();
    if (!refreshToken) return false;
    try {
      const res = await api.post('/api/auth/refresh', {
        refresh_token: refreshToken,
      });
      const { access_token } = res.data;
      saveTokens(access_token, refreshToken);
      set({ accessToken: access_token, isAuthenticated: true });
      return true;
    } catch {
      clearTokens();
      set({
        user: null,
        accessToken: null,
        refreshToken: null,
        isAuthenticated: false,
      });
      return false;
    }
  },

  fetchCurrentUser: async () => {
    try {
      const res = await api.get('/api/auth/me');
      const { authStatusLoaded, accessToken } = get();
      set({
        user: res.data.user,
        isAuthenticated: res.data.authenticated,
        userLoaded: true,
        isLoading: recomputeLoading(authStatusLoaded, true, accessToken),
      });
    } catch {
      const { authStatusLoaded, accessToken } = get();
      set({ userLoaded: true, isLoading: recomputeLoading(authStatusLoaded, true, accessToken) });
    }
  },

  fetchAuthStatus: async () => {
    try {
      const res = await api.get('/api/auth/status');
      const status: AuthStatus = res.data;
      const { userLoaded, accessToken } = get();
      set({
        authRequired: status.auth_required,
        ssoProviders: status.sso_providers || [],
        authStatusLoaded: true,
        isLoading: recomputeLoading(true, userLoaded, accessToken),
      });
    } catch {
      const { userLoaded, accessToken } = get();
      set({
        isLoading: recomputeLoading(true, userLoaded, accessToken),
        authStatusLoaded: true,
        authRequired: false,
      });
    }
  },

  setTokensFromUrl: () => {
    // Read tokens from hash fragment (not query params) to prevent
    // leakage via server logs, Referer headers, and browser history.
    // Hash fragments are never sent to the server in HTTP requests.
    const hash = window.location.hash.replace(/^#/, '');
    const params = new URLSearchParams(hash);
    const access = params.get('access_token');
    const refresh = params.get('refresh_token');
    if (access) {
      saveTokens(access, refresh || '');
      set({
        accessToken: access,
        refreshToken: refresh,
        isAuthenticated: true,
      });
      // Clean URL — remove hash fragment immediately
      window.history.replaceState({}, '', window.location.pathname);
    }
  },

  clearError: () => set({ error: null }),

  hasPermission: (permission: string) => {
    const { user } = get();
    if (!user) return false;
    const perms = ROLE_PERMISSIONS[user.role];
    return perms ? perms.has(permission) : false;
  },
}));

export default useAuthStore;
