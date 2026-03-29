"""AEGIS-UEBA Main API Application"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aegis.core.config import settings
from aegis.core.models import Alert, AlertStatus, Severity, AttackType, EntityType
from aegis.api.feedback import feedback_router

logging.basicConfig(
    level=getattr(logging, settings.app.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

alert_store: Dict[str, Alert] = {}


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
    yield
    logger.info("Shutting down AEGIS-UEBA API...")


app = FastAPI(
    title="AEGIS-UEBA API",
    description="Adaptive Entity Guardian & Intelligent Security System",
    version=settings.app.version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
        timestamp=datetime.utcnow(),
        version=settings.app.version,
        components=components,
    )


@app.get("/api/v1/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats() -> DashboardStats:
    """Get dashboard statistics"""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    stats = {
        "total_alerts": len(alert_store),
        "critical_alerts": 0,
        "high_alerts": 0,
        "medium_alerts": 0,
        "low_alerts": 0,
        "open_alerts": 0,
        "resolved_today": 0,
        "false_positives_today": 0,
    }

    for alert in alert_store.values():
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
) -> AlertListResponse:
    """List alerts with pagination and filters"""
    alerts = list(alert_store.values())

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
async def get_alert(alert_id: str) -> Alert:
    """Get a specific alert"""
    if alert_id not in alert_store:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_store[alert_id]


@app.post("/api/v1/alerts/{alert_id}/assign")
async def assign_alert(alert_id: str, analyst_id: str) -> Dict[str, Any]:
    """Assign an alert to an analyst"""
    if alert_id not in alert_store:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = alert_store[alert_id]
    alert.assigned_to = analyst_id
    alert.status = AlertStatus.IN_PROGRESS

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
) -> Dict[str, Any]:
    """Resolve an alert"""
    if alert_id not in alert_store:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = alert_store[alert_id]
    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = datetime.utcnow()
    alert.resolution_notes = resolution_notes

    return {
        "alert_id": alert_id,
        "status": alert.status.value,
        "resolved_at": alert.resolved_at.isoformat(),
        "message": "Alert resolved successfully",
    }


@app.get("/api/v1/entities/{entity_id}/risk")
async def get_entity_risk_score(entity_id: str) -> Dict[str, Any]:
    """Get risk score for an entity"""
    return {
        "entity_id": entity_id,
        "risk_score": 0.0,
        "last_assessment": datetime.utcnow().isoformat(),
        "factors": [],
    }


@app.get("/api/v1/entities/{entity_id}/behavior")
async def get_entity_behavior(entity_id: str) -> Dict[str, Any]:
    """Get behavior baseline for an entity"""
    return {
        "entity_id": entity_id,
        "baseline_version": 1,
        "features": {},
        "confidence": 0.0,
    }


@app.get("/api/v1/graph/{entity_id}/neighbors")
async def get_entity_neighbors(entity_id: str) -> List[Dict[str, Any]]:
    """Get graph neighbors for an entity"""
    return []


@app.get("/api/v1/system/metrics")
async def get_system_metrics() -> Dict[str, Any]:
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
    alert_store[alert.alert_id] = alert
    return alert
