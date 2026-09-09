// Pages → Worker wiring.
// Same-origin by default (Worker serves the demo itself). Only set a
// cross-origin API base when the frontend (Pages) and API (Worker) are on
// different hosts — and then add that Pages host to ALLOWED_ORIGIN, or
// browsers will block the calls. Never hardcode a workers.dev URL here in
// the repo; configure per-environment at deploy time.
// Example: window.__API_BASE__ = "https://api.example.com";
window.__API_BASE__ = "";
