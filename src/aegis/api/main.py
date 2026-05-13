"""AEGIS-UEBA Main API Application"""

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError

from aegis.core.config import settings
from aegis.core.models import Alert, AlertStatus, Severity, AttackType, EntityType
from aegis.api.feedback import feedback_router

logging.basicConfig(
    level=getattr(logging, settings.app.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# --- Authentication Setup ---
API_KEY_FILE = Path(__file__).resolve().parent.parent.parent.parent / ".api_key"
JWT_SECRET_FILE = Path(__file__).resolve().parent.parent.parent.parent / ".jwt_secret"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def _load_or_generate_key(filepath: Path, length: int = 48) -> str:
    if filepath.exists():
        key = filepath.read_text().strip()
        if key:
            return key
    key = secrets.token_hex(length)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(key + "\n")
    logger.info(f"Generated new key file: {filepath}")
    return key


API_KEY = _load_or_generate_key(API_KEY_FILE)
JWT_SECRET = _load_or_generate_key(JWT_SECRET_FILE, 32)
security = HTTPBearer(auto_error=False)


def verify_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authentication scheme")
    token = credentials.credentials
    if token == API_KEY:
        return {"sub": "system", "type": "api_key"}
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# --- SQLite-backed Alert Store ---
_ALERT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "aegis_alerts.db"
_ALERT_DB_INIT_LOCK = threading.Lock()


def _init_alert_db():
    with _ALERT_DB_INIT_LOCK:
        conn = sqlite3.connect(str(_ALERT_DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()


_init_alert_db()


_alert_db_lock = threading.Lock()


class AlertStore:
    """SQLite-backed alert store"""

    def save(self, alert: Alert) -> None:
        with _alert_db_lock:
            conn = sqlite3.connect(str(_ALERT_DB_PATH))
            conn.execute(
                "INSERT OR REPLACE INTO alerts (alert_id, data) VALUES (?, ?)",
                (alert.alert_id, alert.model_dump_json()),
            )
            conn.commit()
            conn.close()

    def get(self, alert_id: str) -> Optional[Alert]:
        conn = sqlite3.connect(str(_ALERT_DB_PATH))
        row = conn.execute(
            "SELECT data FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        conn.close()
        if row:
            return Alert.model_validate_json(row[0])
        return None

    def all(self) -> List[Alert]:
        conn = sqlite3.connect(str(_ALERT_DB_PATH))
        rows = conn.execute("SELECT data FROM alerts ORDER BY alert_id").fetchall()
        conn.close()
        return [Alert.model_validate_json(row[0]) for row in rows]

    def delete(self, alert_id: str) -> None:
        conn = sqlite3.connect(str(_ALERT_DB_PATH))
        conn.execute("DELETE FROM alerts WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()

    def __len__(self) -> int:
        conn = sqlite3.connect(str(_ALERT_DB_PATH))
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return count


alert_store = AlertStore()


class HealthResponse(BaseModel):
    """Health check response"""

    status: str
    timestamp: datetime
    version: str
    components: Dict[str, str]


class DashboardStats(BaseModel):
    """Dashboard statistics"""

    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    open_alerts: int
    resolved_today: int
    false_positives_today: int


class AlertListResponse(BaseModel):
    """Alert list response"""

    alerts: List[Alert]
    total: int
    page: int
    page_size: int


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    logger.info("Starting AEGIS-UEBA API...")
    if settings.app.environment == "development":
        logger.warning("Running in development mode — authentication is enabled")
    if API_KEY_FILE.exists():
        logger.info(f"API key file: {API_KEY_FILE}")
    yield
    logger.info("Shutting down AEGIS-UEBA API...")


app = FastAPI(
    title="AEGIS-UEBA API",
    description="Adaptive Entity Guardian & Intelligent Security System",
    version=settings.app.version,
    lifespan=lifespan,
)

# CORS: restrict origins based on environment
allowed_origins = os.environ.get(
    "AEGIS_CORS_ORIGINS",
    "http://localhost:3000" if settings.app.environment == "development" else "",
)
cors_origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]
if "*" in cors_origins:
    logger.warning("CORS configured with wildcard origin — this is insecure for production")
if not cors_origins:
    logger.warning("No CORS origins configured — API may not be reachable from browsers")
    cors_origins = ["http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(feedback_router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Check system health"""
    components = {
        "api": "healthy",
        "feature_store": "healthy",
        "graph_db": "healthy",
    }

    all_healthy = all(status == "healthy" for status in components.values())

    return HealthResponse(
        status="healthy" if all_healthy else "degraded",
        timestamp=datetime.now(timezone.utc),
        version=settings.app.version,
        components=components,
    )


@app.post("/auth/login", response_model=LoginResponse)
async def auth_login(request: LoginRequest):
    """Authenticate and receive a JWT token"""
    if not request.username or not request.password:
        raise HTTPException(status_code=422, detail="Username and password required")
    # TODO: Implement proper user authentication against a user store
    # For now, any non-empty credentials are accepted in development mode
    if settings.app.environment != "development":
        raise HTTPException(status_code=403, detail="Authentication disabled in non-development mode")
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    token_data = {"sub": request.username, "exp": expire}
    access_token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return LoginResponse(
        access_token=access_token,
        expires_in=JWT_EXPIRATION_HOURS * 3600,
    )


@app.get("/api/v1/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    auth: Dict[str, Any] = Depends(verify_auth),
) -> DashboardStats:
    """Get dashboard statistics"""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    alerts = alert_store.all()
    stats = {
        "total_alerts": len(alerts),
        "critical_alerts": 0,
        "high_alerts": 0,
        "medium_alerts": 0,
        "low_alerts": 0,
        "open_alerts": 0,
        "resolved_today": 0,
        "false_positives_today": 0,
    }

    for alert in alerts:
        if alert.severity == Severity.CRITICAL:
            stats["critical_alerts"] += 1
        elif alert.severity == Severity.HIGH:
            stats["high_alerts"] += 1
        elif alert.severity == Severity.MEDIUM:
            stats["medium_alerts"] += 1
        elif alert.severity == Severity.LOW:
            stats["low_alerts"] += 1

        if alert.status in [AlertStatus.NEW, AlertStatus.IN_PROGRESS]:
            stats["open_alerts"] += 1

        if alert.resolved_at and alert.resolved_at >= today_start:
            if alert.status == AlertStatus.RESOLVED:
                stats["resolved_today"] += 1
            elif alert.status == AlertStatus.FALSE_POSITIVE:
                stats["false_positives_today"] += 1

    return DashboardStats(**stats)


@app.get("/api/v1/alerts", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    attack_type: Optional[AttackType] = None,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> AlertListResponse:
    """List alerts with pagination and filters"""
    alerts = alert_store.all()

    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    if status:
        alerts = [a for a in alerts if a.status == status]
    if attack_type:
        alerts = [a for a in alerts if a.attack_type == attack_type]

    alerts.sort(key=lambda x: x.timestamp, reverse=True)

    start = (page - 1) * page_size
    end = start + page_size
    paginated_alerts = alerts[start:end]

    return AlertListResponse(
        alerts=paginated_alerts,
        total=len(alerts),
        page=page,
        page_size=page_size,
    )


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Alert:
    """Get a specific alert"""
    alert = alert_store.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/api/v1/alerts/{alert_id}/assign")
async def assign_alert(
    alert_id: str,
    analyst_id: str,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Dict[str, Any]:
    """Assign an alert to an analyst"""
    alert = alert_store.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.assigned_to = analyst_id
    alert.status = AlertStatus.IN_PROGRESS
    alert_store.save(alert)

    return {
        "alert_id": alert_id,
        "assigned_to": analyst_id,
        "status": alert.status.value,
        "message": "Alert assigned successfully",
    }


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution_notes: str = None,
    action_taken: str = None,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Dict[str, Any]:
    """Resolve an alert"""
    alert = alert_store.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolution_notes = resolution_notes
    alert_store.save(alert)

    return {
        "alert_id": alert_id,
        "status": alert.status.value,
        "resolved_at": alert.resolved_at.isoformat(),
        "message": "Alert resolved successfully",
    }


@app.get("/api/v1/entities/{entity_id}/risk")
async def get_entity_risk_score(
    entity_id: str,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Dict[str, Any]:
    """Get risk score for an entity"""
    return {
        "entity_id": entity_id,
        "risk_score": 0.0,
        "last_assessment": datetime.now(timezone.utc).isoformat(),
        "factors": [],
    }


@app.get("/api/v1/entities/{entity_id}/behavior")
async def get_entity_behavior(
    entity_id: str,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Dict[str, Any]:
    """Get behavior baseline for an entity"""
    return {
        "entity_id": entity_id,
        "baseline_version": 1,
        "features": {},
        "confidence": 0.0,
    }


@app.get("/api/v1/graph/{entity_id}/neighbors")
async def get_entity_neighbors(
    entity_id: str,
    auth: Dict[str, Any] = Depends(verify_auth),
) -> List[Dict[str, Any]]:
    """Get graph neighbors for an entity"""
    return []


@app.get("/api/v1/system/metrics")
async def get_system_metrics(
    auth: Dict[str, Any] = Depends(verify_auth),
) -> Dict[str, Any]:
    """Get system performance metrics"""
    return {
        "events_processed": 0,
        "alerts_generated": len(alert_store),
        "avg_processing_time_ms": 0.0,
        "throughput_events_per_sec": 0.0,
    }


def create_alert(
    entity_id: str,
    severity: Severity,
    title: str,
    description: str,
    attack_type: AttackType = AttackType.UNKNOWN,
    confidence: float = 0.5,
    anomaly_score: float = 0.5,
) -> Alert:
    """Helper function to create and store an alert"""
    alert = Alert(
        entity_id=entity_id,
        entity_type=EntityType.USER,
        severity=severity,
        attack_type=attack_type,
        confidence=confidence,
        anomaly_score=anomaly_score,
        title=title,
        description=description,
    )
    alert_store.save(alert)
    return alert
