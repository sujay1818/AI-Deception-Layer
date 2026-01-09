import React from "react";
import { createRoot } from "react-dom/client";
import { ThemeProvider, CssBaseline } from "@mui/material";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { theme } from "./theme.js";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <ThemeProvider theme={theme}>
    <CssBaseline />
    <BrowserRouter basename="/dashboard">
      <App />
    </BrowserRouter>
  </ThemeProvider>
);
