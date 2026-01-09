async function jget(url) {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }
  
  export const api = {
    overview: () => jget("/dashboard/api/overview"),
    sessions: (limit = 200) => jget(`/dashboard/api/sessions?limit=${limit}`),
    alerts: (status = "OPEN", limit = 200) =>
      jget(`/dashboard/api/alerts?status=${encodeURIComponent(status)}&limit=${limit}`),
    session: (session_id, events = 50, deceptions = 50) =>
      jget(`/dashboard/api/session?session_id=${encodeURIComponent(session_id)}&events=${events}&deceptions=${deceptions}`),
  };
  