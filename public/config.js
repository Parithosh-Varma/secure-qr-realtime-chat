// Pages → Worker wiring. The Pages frontend (qrchat.pages.dev) has no API of
// its own — all /api calls MUST go to the Worker. Same-origin ("") would make
// the browser POST to Pages static hosting, which answers 405.
// Worker will read Origin header for CORS, so ALLOWED_ORIGIN must include the Pages host.
window.__API_BASE__ = "https://secure-chat-workers.parithosh.workers.dev";
