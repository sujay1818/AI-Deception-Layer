import React from "react";
import { AppBar, Toolbar, Typography, Box, Button } from "@mui/material";
import { Link, useLocation } from "react-router-dom";

function NavBtn({ to, label }) {
  const loc = useLocation();
  const active = loc.pathname === to;
  return (
    <Button
      component={Link}
      to={to}
      color="inherit"
      sx={{
        textTransform: "none",
        fontWeight: 800,
        opacity: active ? 1 : 0.7,
        borderRadius: 2,
        px: 2,
      }}
    >
      {label}
    </Button>
  );
}

export default function AppLayout({ children }) {
  return (
    <Box
      sx={{
        minHeight: "100vh",
        background:
          "radial-gradient(1200px 600px at 20% 0%, rgba(116,142,255,0.20), transparent 60%)," +
          "radial-gradient(900px 500px at 80% 10%, rgba(255,90,180,0.16), transparent 55%)," +
          "radial-gradient(900px 600px at 50% 90%, rgba(0,255,190,0.10), transparent 55%)," +
          "#0b1220",
      }}
    >
      <AppBar position="sticky" color="transparent" elevation={0} sx={{ backdropFilter: "blur(10px)" }}>
        <Toolbar sx={{ gap: 2, px: { xs: 2, sm: 3, md: 4 } }}>
          <Typography variant="h6" sx={{ fontWeight: 900 }}>
            Honeypot SOC Dashboard
          </Typography>
          <Box sx={{ flex: 1 }} />
          <NavBtn to="/" label="Overview" />
          <NavBtn to="/sessions" label="Sessions" />
          <NavBtn to="/alerts" label="Alerts" />
        </Toolbar>
      </AppBar>

      <Box
        sx={{
          width: "100%",
          minHeight: "calc(100vh - 64px)",
          minWidth: 0,
          display: "flex",
          flexDirection: "column",
          flex: 1,
          py: 2,
          boxSizing: "border-box",
        }}
      >
        {/* INNER WRAPPER: apply padding here, NOT on the flex host */}
        <Box
          sx={{
            width: "100%",
            flex: 1,
            minHeight: 0,
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            px: { xs: 2, sm: 3, md: 4 },
            boxSizing: "border-box",
          }}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
}
