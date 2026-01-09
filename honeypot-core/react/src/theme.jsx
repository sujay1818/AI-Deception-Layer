import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#7c9cff" },
    secondary: { main: "#ff5ab4" },
    background: {
      default: "#0b1220",
      paper: "rgba(255,255,255,0.06)",
    },
  },
  shape: { borderRadius: 14 },
  typography: {
    fontFamily: "Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial",
    h4: { fontWeight: 900, letterSpacing: "-0.02em" },
    h6: { fontWeight: 800 },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: { border: "1px solid rgba(255,255,255,0.10)" },
      },
    },
  },
});
