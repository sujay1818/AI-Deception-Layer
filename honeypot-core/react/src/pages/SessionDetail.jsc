import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { useParams, Link as RLink } from "react-router-dom";
import { Box, Paper, Typography, Tabs, Tab, Button } from "@mui/material";
import DataTable from "../components/DataTable";
import RiskChip from "../components/RiskChip";

export default function SessionDetail() {
  const { sessionId } = useParams();
  const sid = decodeURIComponent(sessionId || "");
  const [tab, setTab] = useState(0);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!sid) return;
    api.session(sid, 50, 50).then(setData).catch(e => setErr(String(e)));
  }, [sid]);

  if (!sid) return <Paper sx={{ p: 2 }}>No session selected.</Paper>;
  if (err) return <Paper sx={{ p: 2 }}>Error: {err}</Paper>;
  if (!data) return <Paper sx={{ p: 2 }}>Loading…</Paper>;

  const s = data.session || {};
  const events = data.events || [];
  const deceptions = data.deceptions || [];

  const eventCols = useMemo(() => ([
    { key: "timestamp", header: "Time", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.timestamp}</span> },
    { key: "method", header: "Method" },
    { key: "path", header: "Path" },
    { key: "ip", header: "IP" },
    { key: "user_agent", header: "User-Agent", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.user_agent}</span> },
  ]), []);

  const deceptionCols = useMemo(() => ([
    { key: "timestamp", header: "Time", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.timestamp}</span> },
    { key: "path", header: "Path" },
    { key: "risk_score", header: "Risk" },
    { key: "flags", header: "Flags", render: (r) => (r.flags || []).join(", ") || "-" },
    {
      key: "intel",
      header: "Intel",
      render: (r) => (
        <span style={{ opacity: 0.75, fontSize: 12 }}>
          {r.credential_intel ? JSON.stringify(r.credential_intel) :
           r.admin_intel ? JSON.stringify(r.admin_intel) : "-"}
        </span>
      )
    },
  ]), []);

  return (
    <Box>
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", gap: 2, flexWrap: "wrap" }}>
          <Box>
            <Typography variant="h6">Session Detail</Typography>
            <Typography variant="body2" color="text.secondary">{sid}</Typography>
          </Box>

          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <Typography variant="body2" color="text.secondary">Max Risk</Typography>
            <Typography sx={{ fontWeight: 900 }}>{s.max_risk ?? 0}</Typography>
            <RiskChip level={s.risk_level} />
            <Button component={RLink} to="/sessions" variant="outlined" size="small">
              Back
            </Button>
          </Box>
        </Box>

        <Box sx={{ mt: 2, display: "flex", gap: 2, flexWrap: "wrap" }}>
          <Box>
            <Typography variant="body2" color="text.secondary">IP</Typography>
            <Typography sx={{ fontWeight: 900 }}>{s.ip || "-"}</Typography>
          </Box>
          <Box sx={{ minWidth: 320 }}>
            <Typography variant="body2" color="text.secondary">User-Agent</Typography>
            <Typography sx={{ fontWeight: 900, fontSize: 13 }}>{s.user_agent || "-"}</Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">Requests</Typography>
            <Typography sx={{ fontWeight: 900 }}>{s.total_requests ?? 0}</Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">Last Seen</Typography>
            <Typography sx={{ fontSize: 13, opacity: 0.85 }}>{s.last_seen || "-"}</Typography>
          </Box>
        </Box>

        <Box sx={{ mt: 2, display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Typography variant="body2" color="text.secondary">Flags:</Typography>
          <Typography variant="body2">{(s.flags || []).join(", ") || "-"}</Typography>
        </Box>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
          <Tab label={`Events (${events.length})`} />
          <Tab label={`Deceptions (${deceptions.length})`} />
        </Tabs>

        {tab === 0 ? (
          <DataTable
            title="Events"
            subtitle="Raw request telemetry"
            columns={eventCols}
            rows={events}
            rowKey={(r) => r.event_id || r.timestamp}
          />
        ) : (
          <DataTable
            title="Deceptions"
            subtitle="Responses served to attacker + intel"
            columns={deceptionCols}
            rows={deceptions}
            rowKey={(r) => r.deception_id || r.timestamp}
          />
        )}
      </Paper>
    </Box>
  );
}
