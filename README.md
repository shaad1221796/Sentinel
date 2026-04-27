# Sentinel IDS — Project Setup & Run Guide

## Project File Structure

```
sentinel-project/
│
├── frontend/                  ← All HTML/CSS files go here
│   ├── sentinel.html          ← Main overview page
│   ├── sentinel.css           ← Styles for sentinel.html
│   ├── login.html             ← Login page
│   ├── register.html          ← Registration page
│   └── upload.html            ← CSV upload & ML analysis page
│
├── backend/                   ← Python API goes here
│   ├── api.py                 ← Flask REST API
│   ├── requirements.txt       ← Python dependencies
│   └── models/                ← Create this folder manually
│       ├── IDS_model.keras    ← Download from Google Drive
│       ├── scaler.save        ← Download from Google Drive
│       └── label_encoder.save ← Download from Google Drive
│
└── database/
    └── sentinel_auth.sql      ← MySQL database schema
```

---

## Prerequisites

Make sure you have these installed before starting:

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10 or 3.11 | https://python.org |
| Node.js (optional, for live server) | 18+ | https://nodejs.org |
| MySQL | 8.0+ | https://mysql.com |
| VS Code (recommended) | Latest | https://code.visualstudio.com |

---

## Step 1 — Download Your ML Model Files

From your Google Colab notebook, run this cell to download the 3 model files:

```python
from google.colab import files
files.download('/content/drive/MyDrive/IDS_model.keras')
files.download('/content/drive/MyDrive/scaler.save')
files.download('/content/drive/MyDrive/label_encoder.save')
```

Then place them inside `backend/models/`:
```
backend/models/IDS_model.keras
backend/models/scaler.save
backend/models/label_encoder.save
```

---

## Step 2 — Set Up the Database

1. Open MySQL Workbench or your terminal
2. Run the SQL script:

```bash
# Option A: terminal
mysql -u root -p < database/sentinel_auth.sql

# Option B: MySQL Workbench
# File → Open SQL Script → select sentinel_auth.sql → Run (lightning bolt)
```

3. Verify it worked:
```sql
USE sentinel_auth;
SHOW TABLES;
-- Should show: users, sessions, login_attempts, etc.
```

---

## Step 3 — Set Up the Python Backend

### 3a. Create a virtual environment (recommended)

```bash
# Windows
cd backend
python -m venv venv
venv\Scripts\activate

# Mac / Linux
cd backend
python3 -m venv venv
source venv/bin/activate
```

### 3b. Install dependencies

```bash
pip install -r requirements.txt
```

This installs: Flask, flask-cors, TensorFlow, joblib, pandas, numpy, scikit-learn.

> Note: TensorFlow installation can take 3–5 minutes. If you get errors on Windows,
> try: pip install tensorflow-cpu instead.

### 3c. Update model paths in api.py

Open `backend/api.py` and update lines 17–19 to match your folder:

```python
# If your folder structure matches above, use:
MODEL_PATH         = "./models/IDS_model.keras"
SCALER_PATH        = "./models/scaler.save"
LABEL_ENCODER_PATH = "./models/label_encoder.save"
```

### 3d. Start the API server

```bash
python api.py
```

You should see:
```
==================================================
  Sentinel IDS Backend API
  Running on http://localhost:5000
==================================================
✓ Model loaded successfully
✓ Scaler loaded successfully
✓ Label Encoder loaded successfully
  Classes: ['BENIGN', 'Bot', 'DDoS', ...]
```

Test it is alive:
```bash
# In a new terminal
curl http://localhost:5000/health
# Returns: {"model_loaded": true, "status": "ok", ...}
```

---

## Step 4 — Run the Frontend

You have two options:

### Option A — VS Code Live Server (recommended)

1. Install the **Live Server** extension in VS Code:
   - Open VS Code → Extensions (Ctrl+Shift+X)
   - Search "Live Server" by Ritwick Dey → Install

2. Open the `frontend/` folder in VS Code

3. Right-click `sentinel.html` → **Open with Live Server**

4. Browser opens at `http://127.0.0.1:5500/sentinel.html`

### Option B — Python simple server

```bash
cd frontend
python -m http.server 8080
```
Then open: `http://localhost:8080/sentinel.html`

### Option C — Just open the file directly

Double-click `sentinel.html` in File Explorer / Finder.
> Note: The CSV upload API connection won't work with `file://` — use Live Server for full functionality.

---

## Step 5 — Switch sentinel.html to use external CSS

When running via Live Server or any real server, replace the embedded `<style>` block
in `sentinel.html` with a clean external link.

Open `sentinel.html`, find the block that starts with:
```html
<!--
  DEPLOYMENT NOTE:
  When running on a local server...
-->
<style>
  /* ... ~1000 lines of CSS ... */
</style>
```

Replace the entire `<style>...</style>` block with this single line:
```html
<link rel="stylesheet" href="sentinel.css">
```

Both files are in the same folder, so it resolves perfectly.

---

## Step 6 — Register and Test

1. Go to `http://localhost:8080/sentinel.html` (or Live Server URL)
2. Click **Register** → fill in your details → submit
3. You'll be redirected back to the overview page, now logged in
4. Click **CSV Upload** in the nav → you'll land on `upload.html`
5. Upload `CICIDS2017_sample_for_app.csv` (the file without the Label column from Colab)
6. The page sends the file to `http://localhost:5000/predict`
7. Results appear: threat count, benign count, distribution bars, prediction table

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `pip install` fails on TensorFlow | Try `pip install tensorflow-cpu` or use Python 3.10/3.11 |
| `Model not loaded` in API | Check the `models/` folder path in `api.py` |
| CSS not loading on sentinel.html | Use Live Server instead of opening the file directly |
| CORS error in browser console | Make sure `api.py` is running and has `CORS(app)` (it does) |
| Login says "invalid email or password" | Register first — accounts are stored in browser localStorage |
| Upload says "API offline" | Start `api.py` in a terminal first |
| MySQL script fails | Check MySQL version is 8.0+ and you're connected as root |

---

## Page Map

| URL | File | Description |
|-----|------|-------------|
| `/sentinel.html` | sentinel.html + sentinel.css | Main landing / overview page |
| `/login.html` | login.html | Sign in page |
| `/register.html` | register.html | Account creation page |
| `/upload.html` | upload.html | CSV upload + CNN prediction results |

---

## How the Pages Connect

```
sentinel.html  ──────────────────────────────────────────┐
      │                                                   │
   [Register]                                        [Login]
      │                                                   │
register.html  ──── creates account ────────────── login.html
      │                                                   │
      └──────────── both redirect to ────────────────────┘
                          │
                   sentinel.html (logged in)
                          │
                    [CSV Upload] nav link
                          │
                    upload.html
                          │
              POST /predict  (api.py)
                          │
              CNN model → predictions
                          │
              Results displayed on page
```
