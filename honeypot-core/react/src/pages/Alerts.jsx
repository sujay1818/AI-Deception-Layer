import React, { useEffect, useState } from "react";
import { Box, FormControl, MenuItem, Select } from "@mui/material";
import { api } from "../api";
import DataTable from "../components/DataTable";
import RiskChip from "../components/RiskChip";
import { Link } from "react-router-dom";

export default function Alerts() {
  const [status, setStatus] = useState("OPEN");
  const [rows, setRows] = useState([]);

  useEffect(() => {
    api.alerts(status, 200).then((r) => setRows(r.alerts || []));
  }, [status]);

  const columns = [
    { key: "timestamp", header: "When", render: (r) => <span style={{ opacity: 0.75, fontSize: 12 }}>{r.timestamp}</span> },
    { key: "severity", header: "Severity", render: (r) => <RiskChip level={r.severity} /> },
    { key: "type", header: "Type" },
    { key: "reason", header: "Reason" },
    { key: "risk", header: "Risk" },
    {
      key: "session_id",
      header: "Session",
      render: (r) => (
        <Box>
          <Box component={Link} to={`/session/${encodeURIComponent(r.session_id)}`} sx={{ fontWeight: 800 }}>
            {r.session_id}
          </Box>
          <Box sx={{ opacity: 0.7, fontSize: 12 }}>{r.ip} • {r.user_agent}</Box>
        </Box>
      ),
    }
  ];

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
        <FormControl size="small">
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            <MenuItem value="OPEN">OPEN</MenuItem>
            <MenuItem value="ACK">ACK</MenuItem>
            <MenuItem value="CLOSED">CLOSED</MenuItem>
          </Select>
        </FormControl>
      </Box>

      <DataTable
        title="Alerts"
        subtitle="High-signal activity requiring attention"
        columns={columns}
        rows={rows}
        rowKey={(r) => r.alert_id}
      />
    </Box>
  );
}
