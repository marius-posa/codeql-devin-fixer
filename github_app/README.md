# GitHub App

The CodeQL Devin Fixer GitHub App provides webhook-driven automation for security scanning. When installed on a repository, it automatically triggers CodeQL analysis on pushes to the default branch and dispatches Devin AI sessions to create fix PRs.

## Prerequisites

- Python 3.11+
- A [Devin API key](https://docs.devin.ai/api-reference/overview) for creating fix sessions
- A GitHub account where you can [create a GitHub App](https://docs.github.com/en/apps/creating-github-apps)

## 1. Create the GitHub App

Go to **GitHub Settings > Developer settings > GitHub Apps > New GitHub App** and configure:

| Setting | Value |
|---------|-------|
| **App name** | Choose a unique name (e.g., `codeql-devin-fixer`) |
| **Homepage URL** | Your server URL or repository URL |
| **Webhook URL** | `https://<your-server>/api/github/webhook` |
| **Webhook secret** | Generate a strong random secret |

### Permissions

| Permission | Access | Purpose |
|------------|--------|---------|
| Contents | Read | Clone repositories for CodeQL analysis |
| Pull requests | Write | Create fix PRs from Devin sessions |
| Security events | Read | Access CodeQL/code scanning alerts |

### Subscribe to Events

- **Installation** -- track when the app is installed/uninstalled
- **Push** -- trigger scans when code is pushed to default branches

After creating the app:
1. Note the **App ID** from the app settings page
2. Click **Generate a private key** and save the downloaded `.pem` file

## 2. Configure Environment

Copy the example environment file and fill in your values:

```bash
cp github_app/.env.example github_app/.env
```

Edit `github_app/.env`:

```bash
# Required
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=./private-key.pem
GITHUB_APP_WEBHOOK_SECRET=your-webhook-secret

# Required for creating Devin fix sessions
DEVIN_API_KEY=your-devin-api-key

# Optional (defaults shown)
SERVER_HOST=0.0.0.0
SERVER_PORT=3000
FLASK_DEBUG=false
LOG_LEVEL=INFO
DEFAULT_BATCH_SIZE=5
DEFAULT_MAX_SESSIONS=25
DEFAULT_SEVERITY_THRESHOLD=low
DEFAULT_QUERIES=security-extended
DEFAULT_BRANCH=main
```

### Required Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_APP_ID` | Numeric App ID from the GitHub App settings page |
| `GITHUB_APP_PRIVATE_KEY_PATH` | Path to the `.pem` private key file downloaded from the app settings |
| `GITHUB_APP_WEBHOOK_SECRET` | The webhook secret you configured when creating the app |
| `DEVIN_API_KEY` | Devin API key for dispatching fix sessions (not needed for dry-run scans) |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HOST` | `0.0.0.0` | Host to bind the server to |
| `SERVER_PORT` | `3000` | Port to listen on |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `DEFAULT_BATCH_SIZE` | `5` | Number of issues per Devin session batch |
| `DEFAULT_MAX_SESSIONS` | `25` | Maximum Devin sessions per scan |
| `DEFAULT_SEVERITY_THRESHOLD` | `low` | Minimum severity to include (`critical`, `high`, `medium`, `low`) |
| `DEFAULT_QUERIES` | `security-extended` | CodeQL query suite to use |
| `DEFAULT_BRANCH` | `main` | Default branch name for repositories |

## 3. Run the Server

### Option A: Direct (from the repository root)

```bash
pip install -r github_app/requirements.txt
python -m github_app
```

The server starts on `http://0.0.0.0:3000` by default.

### Option B: Docker

```bash
docker build -f github_app/Dockerfile -t codeql-fixer-app .
docker run -p 3000:3000 --env-file github_app/.env codeql-fixer-app
```

## 4. Verify the Setup

Check the health endpoint:

```bash
curl http://localhost:3000/healthz
```

Expected response:

```json
{"status": "ok", "app_name": "your-app-name", "app_id": 123456}
```

If the health check returns `{"status": "error", ...}`, verify that:
- `GITHUB_APP_ID` is correct
- `GITHUB_APP_PRIVATE_KEY_PATH` points to a valid `.pem` file
- The private key matches the GitHub App

### Test webhook delivery

Use the **Advanced** tab in your GitHub App settings to redeliver a recent webhook, or install the app on a test repository and push a commit.

Check server logs for:

```
Webhook: event=push delivery=<delivery-id>
```

## 5. Install on Repositories

Go to your GitHub App's public page and click **Install**. Select the repositories you want to monitor. On installation, the app:

1. Receives an `installation` event and logs the installed repositories
2. Updates the local `repo_registry.json` with the installation ID (if the repo is registered)
3. On each push to a default branch, triggers a CodeQL scan and dispatches Devin fix sessions

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check -- returns app name and ID |
| `POST` | `/api/github/webhook` | GitHub webhook receiver (HMAC-verified) |
| `POST` | `/api/github/scan` | Manually trigger a scan for a repository |
| `GET` | `/api/github/installations` | List all app installations |
| `GET` | `/api/github/installations/<id>/repos` | List repos for a specific installation |

### Manual Scan

```bash
curl -X POST http://localhost:3000/api/github/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository": "owner/repo",
    "installation_id": 12345,
    "batch_size": 5,
    "severity_threshold": "high",
    "dry_run": true
  }'
```

### List Installations

```bash
curl http://localhost:3000/api/github/installations
```

## Architecture

```
GitHub webhook (push/installation)
  --> /api/github/webhook
  --> verify_signature (HMAC-SHA256)
  --> route_event
      |
      +--> handle_push (default branch only)
      |      --> trigger_scan
      |            --> fork_repo.py
      |            --> CodeQL analyze
      |            --> parse_sarif.py
      |            --> dispatch_devin.py
      |
      +--> handle_installation
      |      --> update repo_registry.json
      |
      +--> handle_installation_repositories
             --> update repo_registry.json
```

### Authentication Flow

1. The app generates a JWT signed with the RSA private key (valid 10 minutes)
2. The JWT is exchanged for an installation token scoped to the target installation
3. Installation tokens are cached until they expire (with a 60-second safety margin)
4. All webhook payloads are verified via HMAC-SHA256 before processing

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Health check returns 503 | Invalid App ID or private key | Verify `GITHUB_APP_ID` and `GITHUB_APP_PRIVATE_KEY_PATH` |
| Webhook returns 401 | Signature mismatch | Ensure `GITHUB_APP_WEBHOOK_SECRET` matches the value in GitHub App settings |
| Push events ignored | Push to non-default branch | Only pushes to the default branch trigger scans |
| Scan fails at fork step | Token lacks permissions | Ensure the app has `contents: read` permission |
| `ModuleNotFoundError` | Running from wrong directory | Run `python -m github_app` from the repository root, not from inside `github_app/` |

## File Structure

```
github_app/
+-- app.py              # Flask application factory with all route definitions
+-- auth.py             # JWT generation, installation token management, SSRF protection
+-- config.py           # AppConfig dataclass loaded from environment variables
+-- webhook_handler.py  # HMAC signature verification, event routing, registry updates
+-- scan_trigger.py     # Pipeline bridge: fork, clone, parse, dispatch as subprocesses
+-- alerts.py           # Alert formatting and delivery (webhooks, GitHub Issues)
+-- log_utils.py        # Log sanitization (CWE-117 prevention)
+-- main.py             # Server entry point (loads .env, creates app, runs server)
+-- __main__.py         # Enables `python -m github_app`
+-- .env.example        # Example environment file with all available settings
+-- requirements.txt    # Python dependencies
+-- Dockerfile          # Container image definition
```
