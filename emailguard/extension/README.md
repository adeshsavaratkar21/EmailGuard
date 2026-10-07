# EmailGuard Chrome Extension (Manifest V3)

This extension analyzes the active HTTP(S) tab through the same FastAPI `/api/analyze/url` endpoint as the web dashboard. It sends only the current URL, performs a passive analysis by default, and does not navigate, click, or download anything.

## Load unpacked

1. Start the EmailGuard backend on `http://localhost:8000`.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Choose **Load unpacked** and select this `extension/` directory.
4. Open an HTTP(S) page and click the EmailGuard toolbar icon.

The API base is set in `background/service-worker.js`. For a remote development API, update `API_BASE` and add that origin to `host_permissions` in `manifest.json`. The API must allow the extension origin through CORS.

Gmail integration is intentionally out of scope for this first version. No email DOM scraping or automatic mailbox actions are performed.
