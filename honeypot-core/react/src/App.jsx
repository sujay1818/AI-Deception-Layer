import React from "react";
import { Routes, Route } from "react-router-dom";
import AppLayout from "./components/AppLayout.jsx";
import Overview from "./pages/Overview.jsx";
import Sessions from "./pages/Sessions.jsx";
import Alerts from "./pages/Alerts.jsx";
import SessionDetail from "./pages/SessionDetail.jsx";

export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/session/:sessionId" element={<SessionDetail />} />
      </Routes>
    </AppLayout>
  );
}
