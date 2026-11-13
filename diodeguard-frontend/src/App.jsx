import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Navbar  from './components/Navbar';
import Sidebar from './components/Sidebar';
import Login   from './pages/Login';
import Dashboard from './pages/Dashboard';
import Alerts    from './pages/Alerts';
import Threats   from './pages/Threats';
import Traffic   from './pages/Traffic';
import Reports   from './pages/Reports';
import Users     from './pages/Users';

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) return (
    <div className="loading-center" style={{ minHeight: '100vh' }}>
      <div className="spinner" />
    </div>
  );

  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className="app-shell">
      <Navbar />
      <div className="layout">
        <Sidebar unacknowledged={12} />
        <main className="main-content" id="main-content">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/alerts"    element={<Alerts />} />
            <Route path="/threats"   element={<Threats />} />
            <Route path="/traffic"   element={<Traffic />} />
            <Route path="/reports"   element={<Reports />} />
            <Route path="/users"     element={<Users />} />
            <Route path="*"          element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/*"     element={<ProtectedLayout />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
