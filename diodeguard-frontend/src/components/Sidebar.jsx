import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const NAV_LINKS = [
  { to: '/dashboard', icon: '📊', label: 'Dashboard' },
  { to: '/alerts',    icon: '🚨', label: 'Alerts',   badge: true },
  { to: '/threats',   icon: '🎯', label: 'Threats' },
  { to: '/traffic',   icon: '🌐', label: 'Traffic' },
  { to: '/reports',   icon: '📈', label: 'Reports' },
];

const ADMIN_LINKS = [
  { to: '/users', icon: '👥', label: 'Users' },
];

export default function Sidebar({ unacknowledged = 0 }) {
  const { isAdmin } = useAuth();

  return (
    <aside className="sidebar" role="navigation" aria-label="Main navigation">
      <span className="sidebar-section-label">Monitoring</span>
      {NAV_LINKS.map(({ to, icon, label, badge }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
          id={`nav-${label.toLowerCase()}`}
        >
          <span className="sidebar-icon">{icon}</span>
          {label}
          {badge && unacknowledged > 0 && (
            <span className="sidebar-badge">{unacknowledged > 99 ? '99+' : unacknowledged}</span>
          )}
        </NavLink>
      ))}

      {isAdmin && (
        <>
          <span className="sidebar-section-label" style={{ marginTop: '1rem' }}>Admin</span>
          {ADMIN_LINKS.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
              id={`nav-${label.toLowerCase()}`}
            >
              <span className="sidebar-icon">{icon}</span>
              {label}
            </NavLink>
          ))}
        </>
      )}
    </aside>
  );
}
