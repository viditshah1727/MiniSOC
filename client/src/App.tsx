import { lazy } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import { AppLayout, RequireAuth } from './components/layout/AppLayout';
import { AuthProvider } from './context/AuthContext';
import { LiveUpdatesProvider } from './context/LiveUpdatesContext';
import { ToastProvider } from './context/ToastContext';
import LoginPage from './pages/LoginPage';

// Pages load on demand, so the login screen stays small and fast.
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const EventsPage = lazy(() => import('./pages/EventsPage'));
const AlertsPage = lazy(() => import('./pages/AlertsPage'));
const AlertDetailPage = lazy(() => import('./pages/AlertDetailPage'));
const IncidentsPage = lazy(() => import('./pages/IncidentsPage'));
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage'));
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'));
const MitrePage = lazy(() => import('./pages/MitrePage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'));

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              element={
                <RequireAuth>
                  <LiveUpdatesProvider>
                    <AppLayout />
                  </LiveUpdatesProvider>
                </RequireAuth>
              }
            >
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="events" element={<EventsPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="alerts/:id" element={<AlertDetailPage />} />
              <Route path="incidents" element={<IncidentsPage />} />
              <Route path="incidents/:id" element={<IncidentDetailPage />} />
              <Route path="threat-intelligence" element={<ThreatIntelPage />} />
              <Route path="mitre" element={<MitrePage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
