import React from "react";
import { Chip } from "@mui/material";

export default function RiskChip({ level = "LOW" }) {
  const L = String(level).toUpperCase();
  const color =
    L === "CRITICAL" ? "secondary" :
    L === "HIGH" ? "warning" :
    L === "MED" ? "info" : "success";

  return <Chip size="small" label={L} color={color} variant="outlined" />;
}
