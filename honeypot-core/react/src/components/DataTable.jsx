import React from "react";
import {
  Paper, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Typography, Box
} from "@mui/material";

export default function DataTable({
  title,
  subtitle,
  columns,
  rows,
  emptyText = "No data",
  rowKey,
}) {
  return (
    <Paper sx={{ p: 2, height: "100%", display: "flex", flexDirection: "column", minHeight: 0 }}>
      {(title || subtitle) && (
        <Box sx={{ mb: 1, flexShrink: 0 }}>
          {title && <Typography variant="h6">{title}</Typography>}
          {subtitle && (
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>
      )}

      <TableContainer sx={{ flex: 1, overflow: "auto", minHeight: 0 }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              {columns.map((c) => (
                <TableCell
                  key={c.key}
                  sx={{ fontWeight: 800, color: "rgba(255,255,255,0.65)", backgroundColor: "rgba(11, 18, 32, 0.8)" }}
                >
                  {c.header}
                </TableCell>
              ))}
            </TableRow>
          </TableHead>

          <TableBody>
            {!rows || rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length}>
                  <Typography variant="body2" color="text.secondary">
                    {emptyText}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r, idx) => (
                <TableRow key={rowKey ? rowKey(r) : idx} hover>
                  {columns.map((c) => (
                    <TableCell key={c.key}>
                      {c.render ? c.render(r) : String(r?.[c.key] ?? "")}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  );
}
