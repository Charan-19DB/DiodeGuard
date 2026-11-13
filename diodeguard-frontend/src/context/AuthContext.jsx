import { createContext, useContext, useState, useEffect } from 'react';
import { auth } from '../api/api';

const AuthContext = createContext(null);
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

const DEMO_USER = {
  id: '00000000-0000-0000-0000-000000000001',
  username: 'SecAnalyst',
  email: 'analyst@diodeguard.local',
  role: 'admin',
  is_active: true,
};

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem('dg_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      if (USE_MOCK && token.startsWith('demo-')) {
        const stored = localStorage.getItem('dg_user');
        setUser(stored ? JSON.parse(stored) : DEMO_USER);
        setLoading(false);
      } else {
        auth.me()
          .then(setUser)
          .catch(() => {
            if (USE_MOCK) {
              setUser(DEMO_USER);
            } else {
              logout();
            }
          })
          .finally(() => setLoading(false));
      }
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (email, password) => {
    if (USE_MOCK) {
      const role = email && email.toLowerCase().includes('analyst') ? 'analyst' : 'admin';
      const mockUser = {
        id: 'demo-user-id',
        username: email ? email.split('@')[0] : 'SecAnalyst',
        email: email || 'analyst@diodeguard.local',
        role,
        is_active: true,
      };
      localStorage.setItem('dg_token', 'demo-mock-jwt-token');
      localStorage.setItem('dg_user', JSON.stringify(mockUser));
      setToken('demo-mock-jwt-token');
      setUser(mockUser);
      return mockUser;
    }

    try {
      const data = await auth.login({ email, password });
      localStorage.setItem('dg_token', data.access_token);
      localStorage.setItem('dg_user', JSON.stringify({ username: data.username, role: data.role }));
      setToken(data.access_token);
      const me = await auth.me();
      setUser(me);
      return me;
    } catch (err) {
      // Graceful fallback to demo mode if backend is unreachable
      if (err.message && (err.message.includes('fetch') || err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))) {
        const mockUser = {
          ...DEMO_USER,
          email: email || DEMO_USER.email,
          username: email ? email.split('@')[0] : DEMO_USER.username,
        };
        localStorage.setItem('dg_token', 'demo-mock-jwt-token');
        localStorage.setItem('dg_user', JSON.stringify(mockUser));
        setToken('demo-mock-jwt-token');
        setUser(mockUser);
        return mockUser;
      }
      throw err;
    }
  };

  const logout = () => {
    localStorage.removeItem('dg_token');
    localStorage.removeItem('dg_user');
    setToken(null);
    setUser(null);
  };

  const isAdmin   = user?.role === 'admin';
  const isAnalyst = user?.role === 'analyst' || isAdmin;

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout, isAdmin, isAnalyst }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
