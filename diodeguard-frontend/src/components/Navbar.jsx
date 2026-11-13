import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const initials = user?.username?.slice(0, 2).toUpperCase() || 'DG';

  return (
    <header className="navbar" role="banner">
      <Link to="/dashboard" className="navbar-brand">
        <div className="navbar-logo" aria-hidden="true">🛡️</div>
        <span className="navbar-title">DiodeGuard</span>
      </Link>

      <div className="navbar-right">
        <div className="navbar-status" title="Pipeline active — read-only mode">
          <div className="status-dot" aria-hidden="true"></div>
          <span>Pipeline Active</span>
        </div>

        {user && (
          <div className="navbar-user" id="navbar-user-menu">
            <div className="user-avatar" aria-hidden="true">{initials}</div>
            <div className="user-info">
              <span className="user-name">{user.username}</span>
              <span className="user-role">{user.role}</span>
            </div>
          </div>
        )}

        <button
          className="btn-logout"
          onClick={handleLogout}
          id="btn-logout"
          aria-label="Logout"
        >
          Logout
        </button>
      </div>
    </header>
  );
}
