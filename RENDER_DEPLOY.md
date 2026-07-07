# Render deployment notes (Flask + Vercel-style project)

## 1) Use Render for the backend
This repo is a Flask app (single `app.py`) that exposes routes for UI + JSON APIs.

## 2) Required runtime config
The app reads `DATABASE_URL` from environment (see `database.py`).
- If you do **not** set `DATABASE_URL`, it falls back to `sqlite:///sliceguard.db`.
- On managed hosts, using SQLite file storage may fail or reset between deployments.

Recommended: use Postgres and set `DATABASE_URL`.

## 3) Create a Render Postgres database
In Render:
- New → **Postgres**
- Copy the connection string from the database settings.

Render usually gives a URL like:
- `postgresql://USER:PASSWORD@HOST:5432/DBNAME`

## 4) Create a Render Web Service
- New → **Web Service**
- Connect the same repo
Build command: `pip install -r requirements.txt`
- Start command (no gunicorn needed): `python3 -m flask --app app run --host 0.0.0.0 --port $PORT`


## 5) Add environment variable
In your Render Web Service settings:
- `DATABASE_URL` = the Postgres connection string
- (Recommended) `SECRET_KEY` = random string

## 6) Redeploy
Trigger a redeploy.

## 7) Verify
- Visit `/` to load the UI
- `POST /api/auth/login` should work

## 8) Important note about seeding
`app.py` runs `seed_data()` at import time (cold start).
If your DB is slow/unavailable during boot, the process can crash.
Optionally we can patch the app to seed lazily / with retries.

## 9) Python version issue (important)
Your Render logs show SQLAlchemy throwing an AssertionError while importing on Python **3.14**.
Render is auto-selecting Python 3.14.3.

Fix: set the Web Service Python version to **3.11.x** (or 3.10.x) in Render settings, then redeploy.


