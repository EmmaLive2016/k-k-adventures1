# K-K Adventures 1 Backend

This is a **backend-only Render package** built from the working Emma backend pattern.

## What this package does
- Keeps the frontend out of scope.
- Exposes the same auth, comments, journal, stream status, stream start, stream stop, and websocket endpoints.
- Uses **Cloudflare Stream WHIP/WHEP** for live streaming.
- Defaults to the channel name `k-k-adventures1`.
- Forces a **fresh Cloudflare live input on each stream start** by default, which is intended to reduce stale-session problems that often show up as:
  - missing audio after restarting a stream
  - playback freezing after reconnect cycles
  - inconsistent stream recovery after state changes

## Important limitation
The specific issue you described — the video visual freezing when switching between **expand** and **pop-out** — is usually controlled by **frontend media element / WebRTC handling**, not FastAPI. This package strengthens the backend side, but it cannot guarantee a full fix for UI-side cloning or playback-state bugs without the actual K-K frontend code.

## Deploy on Render
1. Upload this folder to GitHub.
2. In Render, create the Blueprint from `render.yaml` or create a Web Service manually.
3. Set these environment variables:
   - `CF_ACCOUNT_ID`
   - `CF_API_TOKEN`
   - `ALLOWED_ORIGINS`
   - `SECRET_KEY` if you do not use the generated value
4. Deploy.

## Endpoints
- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/comments/{channel}`
- `POST /api/comments/{channel}`
- `DELETE /api/comments/{channel}`
- `DELETE /api/comments/{channel}/{comment_id}`
- `GET /api/journal`
- `POST /api/journal`
- `DELETE /api/journal/{entry_id}`
- `GET /api/streams/{channel}`
- `POST /api/streams/{channel}/start`
- `POST /api/streams/{channel}/stop`
- `WS /ws/comments/{channel}`

## Expected channel
By default, the backend only recognizes:
- `k-k-adventures1`

If your existing frontend uses a different channel slug, change:
- `CHANNELS` in environment variables
- `CHANNELS` in `render.yaml`
