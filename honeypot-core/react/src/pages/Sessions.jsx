import React, { useEffect, useMemo, useState } from "react";
import { Box, TextField } from "@mui/material";
import { api } from "../api";
import DataTable from "../components/DataTable";
import RiskChip from "../components/RiskChip";
import { Link } from "react-router-dom";

export default function Sessions() {
  const [rows, setRows] = useState([]);
  const [q, setQ] = useState("");

  useEffect(() => {
    api.sessions(200).then((r) => setRows(r.sessions || []));
  }, []);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rows;
    return rows.filter((x) =>
      String(x.session_id || "").toLowerCase().includes(s) ||
      String(x.ip || "").toLowerCase().includes(s) ||
      String(x.user_agent || "").toLowerCase().includes(s) ||
      String(x.risk_level || "").toLowerCase().includes(s)
    );
  }, [rows, q]);

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
    { key: "total_requests", header: "Requests" },
    { key: "max_risk", header: "Max Risk" },
    { key: "risk_level", header: "Level", render: (r) => <RiskChip level={r.risk_level} /> },
    { key: "last_path", header: "Last Path", render: (r) => r.last_path || "-" },
    { key: "flags", header: "Flags", render: (r) => (r.flags || []).slice(0, 4).join(", ") || "-" },
    { key: "last_seen", header: "Last Seen", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.last_seen}</span> },
  ];

  return (
    <Box>
      <TextField
        fullWidth
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search session, IP, UA, level…"
        sx={{ mb: 2 }}
      />
      <DataTable
        title="Sessions"
        subtitle="Sorted by latest activity"
        columns={columns}
        rows={filtered}
        rowKey={(r) => r.session_id}
      />
    </Box>
  );
}
