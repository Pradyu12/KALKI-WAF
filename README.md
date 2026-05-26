# KALKI WAF - Web Application Firewall

A high-performance Web Application Firewall built with FastAPI that protects your upstream applications from common web attacks including SQLi, XSS, RFI, CMDi, and more.

## Features

- **Real-time threat detection** - Blocks SQL injection, XSS, RFI, command injection, path traversal, and more
- **Dynamic rule management** - Create, update, and toggle security rules via REST API
- **Rate limiting** - Automatic protection against DDoS and brute force attacks
- **Multiple mitigation postures** - Monitor Only, Standard Posture, Under Attack
- **Firebase Firestore backend** - Scalable, serverless database for rules and security events
- **Dashboard UI** - Real-time telemetry and incident monitoring
- **Docker ready** - Containerized deployment with docker-compose

## Getting Started

### Prerequisites

- Python 3.11+
- Firebase project with Firestore enabled
- Docker & Docker Compose (optional)

### Installation

#### Option 1: Direct Installation

```bash
# Clone the repository
git clone https://github.com/your-org/kalki-waf.git
cd kalki-waf

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Create Firebase credentials file
# Download service account key from Firebase Console
# Save as firebase-credentials.json in the project root

# Set environment variables
export FIREBASE_PROJECT_ID=your-project-id
export UPSTREAM_SERVER_URL=http://localhost:8080

# Run the application
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Option 2: Docker Deployment

```bash
# Copy your Firebase credentials to the project root
cp /path/to/firebase-credentials.json .

# Create .env file
cp .env.example .env
# Edit .env with your Firebase project ID

# Build and run
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build
```

### Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Create a new project or select existing one
3. Enable Firestore Database
4. Create a service account:
   - Project Settings → Service Accounts
   - Generate new private key
   - Download JSON file as `firebase-credentials.json`
5. Place the file in your project root

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/api/v1/threat-intel/alerts` | Telemetry data |
| GET | `/api/v1/rules` | List all rules |
| POST | `/api/v1/rules` | Create new rule |
| PUT | `/api/v1/rules/{id}/toggle` | Toggle rule active state |
| DELETE | `/api/v1/rules/{id}` | Delete rule |
| GET | `/api/v1/mitigation-posture` | Get current posture |
| POST | `/api/v1/mitigation-posture` | Update posture |
| POST | `/api/v1/rules/test-sandbox` | Test regex against payload |
| GET | `/api/v1/stream` | SSE real-time events |

## Mitigation Postures

| Posture | Rate Limit | Action |
|---------|------------|--------|
| Monitor Only | 50 req/10s | Logs threats but allows traffic |
| Standard Posture | 50 req/10s | Blocks detected threats |
| Under Attack | 10 req/10s | Aggressive blocking |

## Default Security Rules

- SQLi Core Ruleset (OWASP)
- XSS Aggressive Scrutiny
- Remote File Inclusion (RFI)
- Command Injection Shield
- Path Traversal Protection
- And more...

## Project Structure

```
KALKI-WAF/
├── main.py              # WAF core engine
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker image definition
├── docker-compose.yml   # Multi-container setup
├── schema.sql           # Database schema (for reference)
├── dashboard.html       # Web UI
├── tests/
│   └── test_waf.py      # Test suite
├── upstream/            # Sample upstream server
└── firebase-credentials.json  # Firebase config (not included)
```

## CI/CD

The project includes GitHub Actions CI/CD pipeline:
- Automated testing on PRs
- Docker image build and push on main branch
- GitHub Container Registry integration

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



## Datadog Monitoring

This project includes built-in Datadog integration for metrics, traces, and log collection.

### Architecture

The Datadog Agent runs as a sidecar container alongside the WAF, collecting telemetry via:
- **OpenTelemetry OTLP** - Traces from the WAF FastAPI application forwarded to Datadog APM
- **Prometheus / OpenMetrics** - Metrics (request rate, block rate, latency, etc.) scraped from /metrics
- **Docker Log Collection** - All container logs automatically collected and tagged

### Setup

1. **Get a Datadog API Key**: app.datadoghq.com/organization-settings/api-keys
2. **Set environment variables** (in .env or your CI/CD):

DD_API_KEY=your_api_key_here
DD_SITE=datadoghq.com          # or datadoghq.eu
DD_ENV=production              # or staging / development

3. **Deploy with Docker Compose**:

export DD_API_KEY=your_api_key_here
docker compose up -d --build

### What Gets Monitored

| Data Type | Source | Destination |
|-----------|--------|-------------|
| Application traces | OpenTelemetry (OTLP gRPC, port 4317) | Datadog APM |
| Prometheus metrics | waf:8000/metrics | Datadog Metrics |
| Container logs | Docker daemon | Datadog Logs |
| System metrics | Datadog Agent | Datadog Infrastructure |

### Dashboards & Monitors

Pre-built dashboard and monitor definitions are in the datadog/ directory:

| File | Description |
|------|-------------|
| datadog/dashboard.json | Security Overview dashboard (import via Datadog UI) |
| datadog/monitors/waf-monitors.json | Alert monitors (block rate, timeouts, agent health, latency) |
| datadog/conf.d/openmetrics.d/conf.yaml | Agent-side Prometheus scraping config |
| datadog/conf.d/logs.d/conf.yaml | Log metadata enrichment config |

### Importing Monitors and Dashboards

1. Dashboard: In Datadog - Dashboards - New Dashboard - Import from JSON
2. Monitors: Use the Datadog API or manually recreate from datadog/monitors/waf-monitors.json

### CI/CD Pipeline Integration

The GitLab CI pipeline (.gitlab-ci.yml) includes:
- Git metadata labeling on Docker images for source-to-trace correlation
- Optional datadog-ci trace upload (requires DD_API_KEY in CI variables)
- Unified service tagging (DD_SERVICE, DD_ENV, DD_VERSION) on all artifacts

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DD_API_KEY | (required) | Datadog API key for agent authentication |
| DD_SITE | datadoghq.com | Datadog intake site |
| DD_ENV | production | Deployment environment label |
| DD_AGENT_HOST | datadog-agent | Agent hostname (internal Docker DNS) |
| OTEL_EXPORTER_OTLP_ENDPOINT | http://datadog-agent:4317 | OTLP gRPC endpoint |

## License

This project is licensed under the MIT License.

## Support

- GitHub Issues: [https://github.com/your-org/kalki-waf/issues](https://github.com/your-org/kalki-waf/issues)
- Documentation: [https://github.com/your-org/kalki-waf/wiki](https://github.com/your-org/kalki-waf/wiki)