import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface Toast {
  id: string;
  level: 'success' | 'error' | 'warning' | 'info';
  message: string;
  description?: string;
}

interface UIState {
  sidebarCollapsed: boolean;
  theme: 'light' | 'dark' | 'system';
  toasts: Toast[];
  toggleSidebar: () => void;
  setTheme: (theme: 'light' | 'dark' | 'system') => void;
  addToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      theme: 'system',
      toasts: [],

      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

      setTheme: (theme) => {
        const root = document.documentElement;
        if (theme === 'system') {
          root.removeAttribute('data-theme');
        } else {
          root.setAttribute('data-theme', theme);
        }
        set({ theme });
      },

      addToast: (toast) => {
        const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
        set((s) => ({
          toasts: [...s.toasts, { ...toast, id }].slice(-5),
        }));
        setTimeout(() => {
          set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
        }, 5000);
      },

      removeToast: (id) =>
        set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
    }),
    {
      name: 'openlabels-ui',
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        theme: state.theme,
      }),
    },
  ),
);
