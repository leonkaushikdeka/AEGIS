"""Feedback Loop API - Analyst feedback and model retraining"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from aegis.core.config import settings
from aegis.core.models import Alert, AnalystFeedback, AlertStatus, AttackType

logger = logging.getLogger(__name__)


class FeedbackRequest(BaseModel):
    """Request model for analyst feedback"""

    alert_id: str = Field(..., description="ID of the alert being reviewed")
    analyst_id: str = Field(..., description="ID of the analyst providing feedback")
    is_true_positive: bool = Field(..., description="True if this is a real threat")
    confidence: int = Field(ge=1, le=5, description="Confidence in the classification")
    notes: Optional[str] = Field(None, description="Additional notes")
    corrected_attack_type: Optional[AttackType] = Field(
        None, description="Correct attack type if misclassified"
    )
    suggested_action: Optional[str] = Field(None, description="Suggested remediation action")


class FeedbackResponse(BaseModel):
    """Response model for feedback submission"""

    feedback_id: str
    status: str
    message: str
    timestamp: datetime


class RetrainingStatus(BaseModel):
    """Status of model retraining"""

    status: str
    last_retrain: Optional[datetime]
    next_scheduled: Optional[datetime]
    samples_collected: int
    model_version: str


class FeedbackStore:
    """In-memory storage for feedback (replace with database in production)"""

    def __init__(self):
        self.feedback_store: Dict[str, AnalystFeedback] = {}
        self.alert_feedback_map: Dict[str, str] = {}
        self._retraining_queue: List[Dict[str, Any]] = []
        self._last_retrain: Optional[datetime] = None
        self._model_version: str = "1.0.0"

    def save_feedback(self, feedback: FeedbackRequest) -> AnalystFeedback:
        """Save analyst feedback"""
        feedback_id = str(uuid4())

        feedback_record = AnalystFeedback(
            feedback_id=feedback_id,
            alert_id=feedback.alert_id,
            analyst_id=feedback.analyst_id,
            timestamp=datetime.utcnow(),
            is_true_positive=feedback.is_true_positive,
            confidence=feedback.confidence,
            notes=feedback.notes,
            corrected_attack_type=feedback.corrected_attack_type,
            suggested_action=feedback.suggested_action,
        )

        self.feedback_store[feedback_id] = feedback_record
        self.alert_feedback_map[feedback.alert_id] = feedback_id

        self._retraining_queue.append(
            {
                "feedback_id": feedback_id,
                "alert_id": feedback.alert_id,
                "is_true_positive": feedback.is_true_positive,
                "features": {},
                "timestamp": datetime.utcnow(),
            }
        )

        logger.info(f"Saved feedback {feedback_id} for alert {feedback.alert_id}")
        return feedback_record

    def get_feedback_for_alert(self, alert_id: str) -> List[AnalystFeedback]:
        """Get all feedback for an alert"""
        return [f for f in self.feedback_store.values() if f.alert_id == alert_id]

    def get_retraining_data(self, min_samples: int = 100) -> Dict[str, List[Dict[str, Any]]]:
        """Get data for model retraining"""
        true_positives = [item for item in self._retraining_queue if item["is_true_positive"]]
        false_positives = [item for item in self._retraining_queue if not item["is_true_positive"]]

        return {
            "true_positives": true_positives[:min_samples],
            "false_positives": false_positives[:min_samples],
            "total_samples": len(self._retraining_queue),
        }

    def trigger_retraining(self) -> bool:
        """Trigger model retraining"""
        if len(self._retraining_queue) < settings.feedback.retraining.get("min_samples", 100):
            logger.info("Not enough samples for retraining")
            return False

        self._last_retrain = datetime.utcnow()
        self._model_version = f"{int(self._model_version.split('.')[0]) + 1}.0.0"
        logger.info(f"Triggered model retraining, new version: {self._model_version}")
        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get feedback statistics"""
        true_pos = sum(1 for f in self.feedback_store.values() if f.is_true_positive)
        false_pos = len(self.feedback_store) - true_pos

        return {
            "total_feedback": len(self.feedback_store),
            "true_positives": true_pos,
            "false_positives": false_pos,
            "true_positive_rate": true_pos / max(len(self.feedback_store), 1),
            "pending_retraining_samples": len(self._retraining_queue),
            "last_retrain": self._last_retrain,
            "model_version": self._model_version,
        }


feedback_router = APIRouter(prefix="/feedback", tags=["Feedback Loop"])
feedback_store = FeedbackStore()


@feedback_router.post("/", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest) -> FeedbackResponse:
    """Submit analyst feedback for an alert"""
    feedback = feedback_store.save_feedback(request)

    status = "resolved" if request.is_true_positive else "false_positive"

    return FeedbackResponse(
        feedback_id=feedback.feedback_id,
        status=status,
        message="Feedback recorded successfully",
        timestamp=feedback.timestamp,
    )


@feedback_router.get("/statistics")
async def get_feedback_statistics() -> Dict[str, Any]:
    """Get feedback loop statistics"""
    return feedback_store.get_statistics()


@feedback_router.get("/retraining/status", response_model=RetrainingStatus)
async def get_retraining_status() -> RetrainingStatus:
    """Get model retraining status"""
    stats = feedback_store.get_statistics()
    data = feedback_store.get_retraining_data()

    return RetrainingStatus(
        status="ready" if stats["pending_retraining_samples"] >= 100 else "collecting",
        last_retrain=stats.get("last_retrain"),
        next_scheduled=None,
        samples_collected=data["total_samples"],
        model_version=stats["model_version"],
    )


@feedback_router.post("/retraining/trigger")
async def trigger_retraining(background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Trigger model retraining"""
    success = feedback_store.trigger_retraining()

    if success:
        background_tasks.add_task(run_retraining_job)
        return {"status": "started", "message": "Retraining job started"}
    else:
        return {
            "status": "skipped",
            "message": "Not enough samples for retraining",
            "current_samples": len(feedback_store._retraining_queue),
        }


async def run_retraining_job() -> None:
    """Background task for model retraining"""
    logger.info("Starting model retraining job...")

    try:
        data = feedback_store.get_retraining_data()

        logger.info(
            f"Retraining with {len(data['true_positives'])} positive and "
            f"{len(data['false_positives'])} negative samples"
        )

        await simulate_retraining(data)

        logger.info("Model retraining completed")
    except Exception as e:
        logger.error(f"Error during retraining: {e}")


async def simulate_retraining(data: Dict[str, List]) -> None:
    """Simulate model retraining process"""
    import asyncio

    await asyncio.sleep(2)


@feedback_router.get("/alert/{alert_id}/history")
async def get_alert_feedback_history(alert_id: str) -> List[AnalystFeedback]:
    """Get feedback history for an alert"""
    feedback_list = feedback_store.get_feedback_for_alert(alert_id)
    if not feedback_list:
        raise HTTPException(status_code=404, detail="No feedback found for this alert")
    return feedback_list
