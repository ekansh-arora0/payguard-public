# 🛡️ PayGuard Docker Deployment

This guide explains how to package and run the PayGuard backend using Docker. This is the easiest way to share the project with friends or deploy it to a server.

## Prerequisites

1.  **Docker & Docker Compose**: Install from [docker.com](https://www.docker.com/).
2.  **Git LFS**: The AI model weights are stored using Git LFS. Ensure it's installed before cloning:
    ```bash
    git lfs install
    git clone https://github.com/ekansh-arora0/payguard.git
    ```

## Quick Start

### 3. Run the Backend (Docker)
Open your terminal in the root of the project and run:

```bash
docker-compose up --build
```

This will:
- Spin up a **MongoDB** database.
- Build the **PayGuard Backend** container.
- Install all dependencies (including the DIRE AI model and Tesseract OCR).
- Start the server on `http://localhost:8002`.

### 4. Run the Agent (Local)
The agent needs to run on your local machine to capture your screen and clipboard. 

**On your local machine:**
1. Install requirements:
   ```bash
   pip install -r agent/requirements.txt
   ```
2. Start the agent:
   ```bash
   python agent/agent.py
   ```

## 🖥️ Cross-Platform Support
- **Windows/macOS/Linux**: The **Backend** runs in Docker, so it works exactly the same on all systems.
- **Agent**: The agent uses `pyautogui` and `mss`, which are cross-platform. However, if your friends are on Windows/Linux, they might need to install `tkinter` or `python3-tk` for the alert popups to work correctly.

## 📂 Project Structure for Docker
- `Dockerfile`: Instructions for building the backend image.
- `docker-compose.yml`: Orchestrates the backend and database.
- `requirements.txt`: Combined Python dependencies for Backend + AI.
- `.dockerignore`: Ensures the container remains small by excluding unnecessary files.

## 🛠️ Troubleshooting
- **Port Conflict**: If port `8002` or `27017` is already in use, you can change them in `docker-compose.yml`.
- **Memory**: The AI model requires at least 2GB of RAM allocated to Docker.

## 🔐 Production Security Notes
- Set `PAYGUARD_ALLOW_DEMO_KEY=false` in `.env` (default in `.env.example`).
- Set a strong `PAYGUARD_API_ADMIN_TOKEN` in `.env`.
- API key issuance endpoint `/api/v1/api-key/generate` now requires `X-Admin-Token`.
- Do not expose MongoDB/Redis ports publicly in production.
