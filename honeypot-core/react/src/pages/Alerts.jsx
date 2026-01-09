import React, { useEffect, useState } from "react";
import { Box, FormControl, MenuItem, Select, Paper } from "@mui/material";
import { api } from "../api";
import DataTable from "../components/DataTable";
import RiskChip from "../components/RiskChip";
import { Link } from "react-router-dom";

export default function Alerts() {
  const [status, setStatus] = useState("OPEN");
  const [rows, setRows] = useState([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    setErr("");
    api.alerts(status, 200)
      .then((r) => setRows(r.alerts || []))
      .catch((e) => setErr(String(e)));
  }, [status]);

  const columns = [
    { key: "timestamp", header: "When", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.timestamp || "-"}</span> },
    { key: "severity", header: "Severity", render: (r) => <RiskChip level={r.severity || "LOW"} /> },
    { key: "type", header: "Type" },
    { key: "reason", header: "Reason" },
    { key: "risk", header: "Risk" },
    {
      key: "session_id",
      header: "Session",
      render: (r) => (
        <Box>
          {r.session_id ? (
            <Box component={Link} to={`/session/${encodeURIComponent(r.session_id)}`} sx={{ fontWeight: 800 }}>
              {r.session_id}
            </Box>
          ) : (
            <Box sx={{ fontWeight: 800 }}>-</Box>
          )}
          <Box sx={{ opacity: 0.7, fontSize: 12 }}>
            {[r.ip, r.user_agent].filter(Boolean).join(" • ") || "-"}
          </Box>
        </Box>
      ),
    }
  ];

  if (err) return <Paper sx={{ p: 2 }}>Error: {err}</Paper>;

  return (
    

      <Box sx={{ 
        width: "100%", // Fixed from "full"
        height: "100%", 
        display: "flex", 
        flexDirection: "column", 
        minHeight: 0 
      }}>
        <DataTable
          title="Alerts"
          subtitle="High-signal activity requiring attention"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.alert_id || r.timestamp || Math.random()}
        />
      </Box>
  );
}
