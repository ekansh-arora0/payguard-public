# PayGuard - AI Phishing & Scam Detection

Real-time protection against phishing, crypto scams, fake stores, and credential harvesting.

## Install

### macOS
```bash
curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard/main/install.sh | bash
```

### Windows
```bash
git clone https://github.com/ekansh-arora0/payguard.git
cd payguard
pip install pystray Pillow httpx xgboost numpy scikit-learn requests joblib
python payguard/payguard_windows.py
```

Look for the shield icon in your menu bar.

## How It Works

### Detection Layers

| Layer | What It Catches |
|-------|----------------|
| Domain tier | Lookalikes (paypa1.com), suspicious TLDs (.top, .xyz), brand impersonation |
| Page analyzer | New domains, SPA shells, identity mismatch, payment analysis, tiny redirect pages |
| JS analyzer | Obfuscated phishing kit scripts (hex vars, string arrays, hidden redirects) |
| Reputation | Known malicious URLs from OpenPhish, PhishTank, URLhaus feeds |
| Text analyzer | Scam phrases, urgency + demand patterns, crypto scam signals |

### Speed

- Neutral domains (github.com, google.com): **<0.5s**
- Suspicious domains (okxweb3.io): **<1s**
- Full page analysis (schutzsale.shop): **3-4s**

### What It Catches

- `paypa1.com` → lookalike detection
- `secure-chase-banking.com` → brand impersonation
- `palmeirasstore-online.top` → new domain + SPA shell + suspicious TLD
- `auroraproject.site` → 1-day-old domain + identity mismatch
- `okxweb3.io` → crypto airdrop scam
- `rosyquartzwb.name/dvea` → tiny redirect page + obfuscated JS
- `juvo.sentraxis.st/.../index.php` → hex-obfuscated phishing kit redirect

## Architecture

```
Screen → OCR → URL Extraction → URL Analysis (parallel)
  │                        │
  │                        ├── Reputation (instant)
  │                        ├── Domain tier (instant)
  │                        ├── URL structure (instant)
  │                        ├── Page analyzer (1-3s, with timeout)
  │                        └── JS analyzer (runs on HTML)
  │
  └── Behavioral text analysis (runs on OCR text)
```

## Files

| File | Purpose |
|------|---------|
| `detector.py` | Main menu bar app (rumps) |
| `page_analyzer.py` | Page structural analysis (forms, iframes, scripts, identity) |
| `js_analyzer.py` | JavaScript obfuscation detection (trained on 1978 phishing kits) |
| `backend/` | Risk engine, auth, reputation service, models |
| `models/` | XGBoost models (URL + JS) |
| `setup.py` | Package installer |

## Configuration

```bash
# Run
python3 payguard/detector.py

# Scan interval (default: 3 seconds)
# Alert cooldown (default: 10 seconds)
# Edit in detector.py __init__
```

## Privacy

- All processing happens locally
- No data sent to cloud
- No telemetry without consent

## License

MIT
