# Sovereign Manifold Retro Wallet

Welcome to the Sovereign Manifold Retro Wallet. This wallet is a self-contained, offline-first application. 

> [!IMPORTANT]
> **EVM Wallet Security Constraint**: Injected wallet extensions (Rabby, MetaMask, etc.) require a valid host domain origin (such as `http://localhost`). Browsers report the origin of pages loaded directly from disk via `file://` as `null` / `none`, which causes wallet providers to reject connection requests. Therefore, **you must run a local web server to use this application.**

---

## Quick-Start Options by Platform

### 1. Linux & macOS
You can use Python or Node/npm to serve the folder:

- **Using Python (Recommended)**:
  Run the included startup script:
  ```bash
  chmod +x run-local-server.sh
  ./run-local-server.sh
  ```
  Or manually run:
  ```bash
  python3 -m http.server 8080
  ```
  Then open [http://localhost:8080](http://localhost:8080) in your browser.

- **Using Node.js**:
  ```bash
  npx serve
  ```

---

### 2. Windows
- **Using Double-Click Script (Recommended)**:
  Double-click `run-local-server.bat` in this directory to automatically launch a Python HTTP server and open the browser.

- **Using Node.js / npm**:
  Open Command Prompt or PowerShell and run:
  ```cmd
  npx serve
  ```

- **Using VS Code (Live Server Extension)**:
  1. Open the `wallet/app` directory in VS Code.
  2. Install the **Live Server** extension by Ritwick Dey.
  3. Click **Go Live** in the status bar at the bottom right.

---

## Architecture & DID Resolution
- **Primary Identity**: Your connected standard EVM wallet address.
- **Key Patching**: Upon password setup, the app generates auxiliary curves (Ed25519, BLS, and post-quantum keys like ML-DSA, SLH-DSA, Falcon) locally.
- **Keystore Separation**: Public keys are exported to the W3C `did.json` document. Your private keys (auxiliary seed phrase) are saved separately in an encrypted keystore (`keystore.enc.json`) in your storage directory.
