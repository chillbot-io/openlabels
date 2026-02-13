import { useLocation, Link } from 'react-router';

const PATH_LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  explorer: 'Resource Explorer',
  events: 'Events',
  results: 'Scan Results',
  scans: 'Scans',
  labels: 'Labels',
  sync: 'Sync',
  permissions: 'Permissions',
  remediation: 'Remediation',
  policies: 'Policies',
  targets: 'Targets',
  schedules: 'Schedules',
  monitoring: 'Monitoring',
  reports: 'Reports',
  settings: 'Settings',
  new: 'New',
};

export function Breadcrumbs() {
  const location = useLocation();
  const segments = location.pathname.split('/').filter(Boolean);

  if (segments.length <= 1) return null;

  return (
    <nav aria-label="Breadcrumb" className="px-6 py-2 text-sm text-[var(--muted-foreground)]">
      <ol className="flex items-center gap-1.5">
        {segments.map((segment, index) => {
          const path = '/' + segments.slice(0, index + 1).join('/');
          const label = PATH_LABELS[segment] ?? segment;
          const isLast = index === segments.length - 1;

          return (
            <li key={path} className="flex items-center gap-1.5">
              {index > 0 && <span aria-hidden="true">/</span>}
              {isLast ? (
                <span className="font-medium text-[var(--foreground)]" aria-current="page">{label}</span>
              ) : (
                <Link to={path} className="hover:text-[var(--foreground)]">{label}</Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
