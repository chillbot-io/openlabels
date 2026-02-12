import { NavLink } from 'react-router';
import {
  LayoutDashboard, FolderTree, Activity, FileSearch, Scan, Tag,
  Shield, ShieldAlert, BookOpen, Target, Calendar, Monitor,
  BarChart3, Settings, ChevronLeft, ChevronRight,
} from 'lucide-react';
import { cn } from '@/lib/utils.ts';
import { NAV_GROUPS } from '@/lib/constants.ts';
import { useUIStore } from '@/stores/ui-store.ts';

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  LayoutDashboard, FolderTree, Activity, FileSearch, Scan, Tag,
  Shield, ShieldAlert, BookOpen, Target, Calendar, Monitor,
  BarChart3, Settings,
};

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggle = useUIStore((s) => s.toggleSidebar);

  return (
    <aside
      className={cn(
        'flex h-screen flex-col bg-sidebar text-sidebar-foreground transition-all duration-200',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-white/10 px-4">
        <Shield className="h-6 w-6 shrink-0 text-primary-400" />
        {!collapsed && <span className="text-lg font-bold">OpenLabels</span>}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4" aria-label="Main navigation">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4">
            {!collapsed && (
              <p className="mb-1 px-4 text-[10px] font-semibold uppercase tracking-wider text-gray-400">
                {group.label}
              </p>
            )}
            {group.items.map((item) => {
              const Icon = ICON_MAP[item.icon];
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-sidebar-hover',
                      isActive && 'bg-sidebar-active font-medium text-white',
                      collapsed && 'justify-center px-0',
                    )
                  }
                >
                  {Icon && <Icon className="h-4 w-4 shrink-0" />}
                  {!collapsed && <span>{item.label}</span>}
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={toggle}
        className="flex h-10 items-center justify-center border-t border-white/10 text-gray-400 hover:text-white"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </button>
    </aside>
  );
}
