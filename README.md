# AEGIS-UEBA

Adaptive Entity Guardian & Intelligent Security System

An enterprise-grade AI-Driven Security Operations Center (SOC) platform that uses machine learning to detect zero-day threats, insider attacks, and compromised accounts in real-time using unsupervised learning and graph theory.

![AEGIS-UEBA](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

## Features

- **Data Ingestion Pipeline** - High-throughput ingestion from Windows, Linux, CloudTrail, DNS, and more
- **Feature Engineering Engine** - Extract behavioral features including frequency, entropy, geo-spatial, and graph-based features
- **Multi-Model Detection** - Ensemble of Isolation Forest, Autoencoder, and XGBoost models
- **Explainable AI** - SHAP and LIME integration for model explanations
- **Graph Analysis** - Neo4j integration for entity relationship analysis
- **Feedback Loop** - Analyst feedback integration for continuous model improvement

## Architecture

```
+------------------------------------------------------------------+
|                     AEGIS-UEBA Platform                           |
+------------------------------------------------------------------+
|  Data Sources                                                    |
|  ├── Windows Event Logs                                          |
|  ├── Linux Syslogs                                               |
|  ├── AWS CloudTrail                                              |
|  ├── DNS Queries                                                 |
|  └── Firewall/Proxy Logs                                         |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                Ingestion Pipeline (Kafka)                         |
|  ├── Log Normalizers (Windows, Linux, CloudTrail, OCSF)          |
|  └── Event Normalization                                          |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                Feature Engineering Engine                         |
|  ├── Frequency Extractor                                          |
|  ├── Entropy Extractor                                            |
|  ├── Geo-Spatial Extractor                                        |
|  ├── Time-Series Extractor                                        |
|  └── Graph Extractor                                              |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                ML Detection Ensemble                              |
|  ├── Isolation Forest (Unsupervised)                              |
|  ├── Autoencoder (Unsupervised)                                   |
|  └── XGBoost (Supervised)                                         |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                Explainable AI (SHAP/LIME)                         |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                Graph Database (Neo4j)                             |
+------------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------------+
|                Feedback Loop API                                  |
|  ├── Analyst Feedback                                             |
|  └── Model Retraining                                             |
+------------------------------------------------------------------+
```

## Quick Start

### Prerequisites

- Python 3.10+
- Apache Kafka (optional, for real-time ingestion)
- Redis (optional, for feature storage)
- Neo4j (optional, for graph analysis)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/AEGIS.git
cd AEGIS

# Install dependencies
pip install -e .

# Copy configuration
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
```

### Running the Demo

```bash
python test_demo.py
```

### Running the API Server

```bash
python -m uvicorn aegis.api.main:app --host 0.0.0.0 --port 8080
```

## API Endpoints

### Health Check
```
GET /health
```

### Dashboard Statistics
```
GET /api/v1/dashboard/stats
```

### Alerts
```
GET  /api/v1/alerts              # List alerts with pagination
GET  /api/v1/alerts/{alert_id}   # Get specific alert
POST /api/v1/alerts/{alert_id}/assign   # Assign alert to analyst
POST /api/v1/alerts/{alert_id}/resolve  # Resolve alert
```

### Feedback Loop
```
POST /api/v1/feedback            # Submit analyst feedback
GET  /api/v1/feedback/stats      # Get feedback statistics
GET  /api/v1/feedback/retraining/status  # Get retraining status
POST /api/v1/feedback/retraining/trigger # Trigger model retraining
```

### Entity Analysis
```
GET /api/v1/entities/{entity_id}/risk      # Get risk score
GET /api/v1/entities/{entity_id}/behavior  # Get behavior baseline
GET /api/v1/graph/{entity_id}/neighbors    # Get graph neighbors
```

## Configuration

All configuration is managed through `config.yaml`:

```yaml
# Application Settings
app:
  name: "AEGIS-UEBA"
  version: "1.0.0"
  environment: "development"
  log_level: "INFO"

# Kafka Configuration
kafka:
  bootstrap_servers:
    - "localhost:9092"
  topics:
    raw_logs: "aegis.raw_logs"
    normalized: "aegis.normalized"
    alerts: "aegis.alerts"

# Redis Configuration
redis:
  host: "localhost"
  port: 6379
  key_prefix: "aegis:"

# Neo4j Configuration
neo4j:
  uri: "bolt://localhost:7687"
  user: "neo4j"
  password: "password"

# ML Model Configuration
models:
  isolation_forest:
    contamination: 0.01
    n_estimators: 200
  autoencoder:
    encoding_dim: 32
    hidden_layers: [128, 64, 32]
  xgboost:
    n_estimators: 200
    max_depth: 6
```

## Project Structure

```
AEGIS/
├── config.yaml              # Main configuration file
├── pyproject.toml           # Poetry project config
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── test_demo.py             # Demo script
└── src/aegis/
    ├── core/
    │   ├── config.py       # Configuration management
    │   └── models.py       # Data models
    ├── pipeline/
    │   └── ingestion.py    # Kafka ingestion, log normalizers
    ├── features/
    │   ├── engine.py       # Feature extraction orchestration
    │   ├── extractors.py   # Feature extractors
    │   └── store.py        # Redis feature store
    ├── ml/
    │   ├── detectors.py    # ML detection models
    │   └── xai.py          # Explainable AI
    ├── graph/
    │   └── database.py     # Neo4j connector
    ├── api/
    │   ├── main.py         # FastAPI application
    │   └── feedback.py     # Feedback loop API
    ├── data/
    │   └── generator.py    # Synthetic data generator
    └── main.py             # Entry point
```

## ML Models

### 1. Isolation Forest
- Unsupervised anomaly detection
- Good for detecting outliers in high-dimensional data
- Configurable contamination rate

### 2. Autoencoder
- Neural network-based anomaly detection
- Learns to reconstruct "normal" behavior
- Reconstruction error indicates anomaly score

### 3. XGBoost
- Supervised classification
- Trained on labeled attack datasets
- Detects known attack patterns

## Feature Engineering

The system extracts 50+ behavioral features across multiple time windows (1h, 24h, 7d):

- **Frequency Features**: Login counts, unique hosts/IPs, event frequencies
- **Entropy Features**: Shannon entropy of IPs, hostnames, event types
- **Geo-Spatial Features**: Distance calculations, velocity checks, location diversity
- **Time-Series Features**: Periodicity, burst detection, night/weekend activity
- **Graph Features**: Degree centrality, clustering coefficient, connection diversity

## Explainable AI

When an anomaly is detected, the system generates natural language explanations:

```
Alert triggered due to multiple factors: unusual w3600_login_count,
unusual w3600_unique_hosts, unusual w3600_unique_ips,
unusual w3600_avg_events_per_hour, and somewhat unusual w3600_failed_logins.
```

## Graph Analysis

Neo4j integration enables:
- Entity relationship mapping
- Lateral movement detection
- Degree centrality calculation
- Shortest path analysis
- Clustering coefficient

## Development

```bash
# Run tests
pytest tests/

# Run linting
black src/aegis/
isort src/aegis/
mypy src/aegis/

# Format code
black src/aegis/
```

## Deployment

### Docker

```dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8080

CMD ["uvicorn", "aegis.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### Kubernetes

Deploy using the provided Helm chart or Kubernetes manifests.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and feature requests, please open a GitHub issue.

---

Built with security and intelligence in mind.
