"""AEGIS-UEBA - Adaptive Entity Guardian & Intelligent Security System

Enterprise-grade AI-Driven Security Operations Center Platform
"""

__version__ = "1.0.0"
__author__ = "AEGIS Team"

from aegis.core.config import settings
from aegis.core.models import Alert, Event, Entity
from aegis.pipeline import EventIngestionPipeline
from aegis.features import FeatureEngineeringEngine, FeatureStore
from aegis.ml import EnsembleDetector
from aegis.ml.explainability import ExplainableAI
from aegis.graph import GraphDatabaseManager
from aegis.api.main import app, create_alert

__all__ = [
    "settings",
    "Alert",
    "Event",
    "Entity",
    "EventIngestionPipeline",
    "FeatureEngineeringEngine",
    "FeatureStore",
    "EnsembleDetector",
    "ExplainableAI",
    "GraphDatabaseManager",
    "app",
    "create_alert",
]


def create_aegis_engine():
    """Create and configure the AEGIS engine"""
    pipeline = EventIngestionPipeline()
    feature_engine = FeatureEngineeringEngine()
    feature_store = FeatureStore()
    detector = EnsembleDetector()
    explainer = ExplainableAI()
    graph_db = GraphDatabaseManager()

    return {
        "pipeline": pipeline,
        "feature_engine": feature_engine,
        "feature_store": feature_store,
        "detector": detector,
        "explainer": explainer,
        "graph_db": graph_db,
    }
