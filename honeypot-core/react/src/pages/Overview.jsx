import React, { useEffect, useState } from "react";
import { api } from "../api";
import { Grid, Paper, Typography, Box } from "@mui/material";
import DataTable from "../components/DataTable";
import RiskChip from "../components/RiskChip";
import { Link } from "react-router-dom";

function Stat({ label, value, sub }) {
  return (
    <Paper sx={{ p: 2 }}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography variant="h4" sx={{ fontWeight: 900, mt: 0.5 }}>{value}</Typography>
      {sub ? <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{sub}</Typography> : null}
    </Paper>
  );
}

export default function Overview() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.overview().then(setData).catch(e => setErr(String(e)));
  }, []);
  console.log(setData);

  if (err) return <Paper sx={{ p: 2 }}>Error: {err}</Paper>;
  if (!data) return <Paper sx={{ p: 2 }}>Loading…</Paper>;
  if (!data.ok) return <Paper sx={{ p: 2 }}>Backend not ready.</Paper>;

  const levels = data.by_level || {};
  const top = data.top_sessions || [];

  const columns = [
    {
      key: "session_id",
      header: "Session",
      render: (r) => (
        <Box>
          <Box component={Link} to={`/session/${encodeURIComponent(r.session_id)}`} sx={{ fontWeight: 800 }}>
            {r.session_id}
          </Box>
          <Box sx={{ opacity: 0.7, fontSize: 12 }}>{r.user_agent}</Box>
        </Box>
      )
    },
    { key: "ip", header: "IP" },
    { key: "max_risk", header: "Max Risk" },
    { key: "risk_level", header: "Level", render: (r) => <RiskChip level={r.risk_level} /> },
    { key: "last_seen", header: "Last Seen", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.last_seen}</span> },
  ];

  return (
    <Box>
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Stat label="Total Sessions" value={data.total_sessions} sub="Unique IP + User-Agent combos" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Stat label="Open Alerts" value={data.open_alerts} sub="Needs attention" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Stat label="Critical Sessions" value={levels.CRITICAL || 0} sub="Risk ≥ 80" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Stat label="High Sessions" value={levels.HIGH || 0} sub="Risk 60–79" />
        </Grid>
      </Grid>

      <DataTable
        title="Top Risk Sessions"
        subtitle="Highest max_risk first"
        columns={columns}
        rows={top}
        rowKey={(r) => r.session_id}
      />
    </Box>
  );
}
