import { useEffect, useState } from 'react';
import { users as usersApi } from '../api/api';
import { useAuth } from '../context/AuthContext';

const MOCK_USERS = [
  { id: 'u1', username: 'admin', email: 'admin@diodeguard.io', role: 'admin', is_active: true, created_at: new Date().toISOString(), last_login: new Date().toISOString() },
  { id: 'u2', username: 'analyst1', email: 'analyst1@diodeguard.io', role: 'analyst', is_active: true, created_at: new Date().toISOString(), last_login: new Date().toISOString() },
];

export default function Users() {
  const { isAdmin } = useAuth();
  const [data, setData]     = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isAdmin) return;
    usersApi.list()
      .then(setData)
      .catch(() => setData(MOCK_USERS))
      .finally(() => setLoading(false));
  }, []);

  const handleRoleChange = async (id, role) => {
    try { await usersApi.updateRole(id, role); }
    catch {}
    setData((prev) => prev.map((u) => u.id === id ? { ...u, role } : u));
  };

  const handleDeactivate = async (id) => {
    if (!confirm('Deactivate this user?')) return;
    try { await usersApi.deactivate(id); }
    catch {}
    setData((prev) => prev.map((u) => u.id === id ? { ...u, is_active: false } : u));
  };

  if (!isAdmin) return (
    <div className="empty-state">
      <div className="empty-state-icon">🔒</div>
      <p>Admin access required.</p>
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div className="page-title-group">
          <h1 className="page-title">User Management</h1>
          <p className="page-subtitle">Admin-only · Manage analyst and admin accounts</p>
        </div>
      </div>

      {loading ? (
        <div className="loading-center"><div className="spinner" /></div>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Username</th><th>Email</th><th>Role</th>
                <th>Status</th><th>Last Login</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id} id={`user-row-${u.id}`}>
                  <td className="td-primary">{u.username}</td>
                  <td className="td-mono">{u.email}</td>
                  <td>
                    <select
                      id={`role-select-${u.id}`}
                      className="filter-select"
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      style={{ fontSize: '0.8rem' }}
                    >
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td>
                    <span style={{
                      color: u.is_active ? 'var(--severity-low)' : 'var(--text-muted)',
                      fontWeight: 600, fontSize: '0.8rem',
                    }}>
                      {u.is_active ? '● Active' : '○ Inactive'}
                    </span>
                  </td>
                  <td className="td-mono">
                    {u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                  </td>
                  <td>
                    {u.is_active && (
                      <button
                        id={`btn-deactivate-${u.id}`}
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDeactivate(u.id)}
                      >
                        Deactivate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
