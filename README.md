# AK Redirector

Anti-bypass one-time-use link redirector with Firebase.

## Local Development

1. Put `serviceAccountKey.json` in the project root.
2. Copy `.env.example` to `.env` and fill in the values.
3. Install and run:

```bash
pip install -r requirements.txt
python api/index.py
```

4. Admin panel: `http://127.0.0.1:8999/admin?key=YOUR_ADMIN_KEY`

## Deploy on Vercel

1. Push this repo to GitHub (do **not** commit `serviceAccountKey.json` or `.env`).
2. Import the repo at https://vercel.com/new
3. Add environment variables (Settings → Environment Variables):
   - `FIREBASE_SERVICE_ACCOUNT_KEY` → paste the **entire contents** of `serviceAccountKey.json`
   - `FIREBASE_RTDB_URL` → your RTDB URL
   - `ADMIN_KEY`, `GATE_KEY`
   - `SHRINKEARN_API_KEY`
   - `PUBLIC_BASE_URL` → `https://your-project.vercel.app`
   - All `BRAND_*` vars
4. Deploy.
5. Open `https://your-project.vercel.app/admin?key=ADMIN_KEY`

## API Reference

All admin endpoints require either `?key=ADMIN_KEY` or `X-Admin-Key: ADMIN_KEY`.

### One-shot: register + shorten

```bash
curl -X POST "https://your-project.vercel.app/api/shorten" \
     -H "X-Admin-Key: YOUR_ADMIN_KEY" \
     -H "Content-Type: application/json" \
     -d '{"id":"529596","url":"https://t.me/AKM_Files_Store_Bot?start=529596","alias":"Mod_A"}'
```

Response:

```json
{
  "ok": true,
  "id": "529596",
  "gate_url": "https://your-project.vercel.app/gate?k=...&t=529596",
  "short_url": "https://tpi.li/Mod_A"
}
```

### Register only

```bash
curl "https://your-project.vercel.app/api/register?id=529596&url=https://t.me/...&key=ADMIN_KEY"
```

### List files

```bash
curl "https://your-project.vercel.app/api/links?key=ADMIN_KEY"
```

### Bypass log

```bash
curl "https://your-project.vercel.app/api/bypasses?key=ADMIN_KEY"
```

## What Goes in ShrinkEarn

For each file, the destination is:

```
https://your-project.vercel.app/gate?k=GATE_KEY&t=FILE_ID
```

Example:

```
https://your-project.vercel.app/gate?k=static-gate-key-change-me&t=529596
```

The `/api/shorten` endpoint handles the ShrinkEarn call for you.
