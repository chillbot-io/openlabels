import { create } from 'zustand';
import { apiFetch } from '@/api/client.ts';
import type { User } from '@/api/types.ts';

interface MeResponse {
  id: string;
  email: string;
  name: string;
  tenant_id: string;
  roles: string[];
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  checkAuth: () => Promise<void>;
  logout: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  checkAuth: async () => {
    try {
      const me = await apiFetch<MeResponse>('/auth/me');
      const user: User = {
        id: me.id,
        email: me.email,
        name: me.name,
        tenant_id: me.tenant_id,
        role: me.roles?.includes('admin') ? 'admin' : me.roles?.includes('viewer') ? 'viewer' : 'user',
        created_at: '',
      };
      set({ user, isAuthenticated: true, isLoading: false });
    } catch {
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },

  logout: async () => {
    try {
      await apiFetch('/auth/logout', { method: 'POST' });
    } finally {
      set({ user: null, isAuthenticated: false });
      window.location.href = '/login';
    }
  },
}));
