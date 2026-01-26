#!/usr/bin/env python
"""
AEGIS-UEBA Demo Script - Demonstrates the complete system functionality
"""

import sys
from datetime import datetime, timedelta
import numpy as np

from aegis.core.config import settings
from aegis.core.models import (
    NormalizedEvent,
    EventType,
    EntityType,
    FeatureVector,
    Alert,
    Severity,
    AttackType,
)
from aegis.features.engine import FeatureEngineeringEngine
from aegis.features.extractors import (
    FrequencyExtractor,
    EntropyExtractor,
    GeoSpatialExtractor,
    TimeSeriesExtractor,
    GraphExtractor,
)
from aegis.ml.detectors import (
    IsolationForestModel,
    AutoencoderModel,
    XGBoostModel,
    EnsembleDetector,
)
from aegis.ml.xai import ExplainableAI
from aegis.data.generator import SyntheticDataGenerator


def print_header(title: str) -> None:
    """Print formatted header"""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def generate_test_events() -> list:
    """Generate test events for demonstration"""
    print("Generating synthetic security events...")

    generator = SyntheticDataGenerator()
    events = []

    for i in range(50):
        event = generator.generate_event("windows")
        event["event_id"] = f"evt_{i:04d}"
        event["timestamp"] = (
            datetime.utcnow() - timedelta(hours=1, minutes=i)
        ).isoformat()
        events.append(event)

    print(f"  Generated {len(events)} events")
    return events, generator


def demonstrate_feature_extraction(events: list) -> dict:
    """Demonstrate feature extraction"""
    print_header("Feature Engineering Engine")

    engine = FeatureEngineeringEngine()
    normalizer = None

    from aegis.pipeline.ingestion import EventIngestionPipeline

    pipeline = EventIngestionPipeline()

    normalized_events = []
    for raw_event in events[:20]:
        normalized = pipeline.normalize_event(raw_event, "windows")
        if normalized:
            normalized_events.append(normalized)

    print(f"  Normalized {len(normalized_events)} events")

    engine.add_events_batch(normalized_events)

    for entity_id in engine.entity_events.keys():
        features = engine.get_flattened_features(entity_id)
        print(f"\n  Entity: {entity_id}")
        print(f"  Features extracted: {len(features)}")

        feature_names = list(features.keys())[:5]
        print(f"  Sample features: {feature_names}...")

        return {
            "features": features,
            "entity_id": entity_id,
            "feature_count": len(features),
        }

    return {}


def demonstrate_ml_detection(features: dict, feature_names: list) -> dict:
    """Demonstrate ML detection models"""
    print_header("ML Detection Ensemble")

    feature_values = np.array([[features.get(f, 0) for f in feature_names]])

    print(f"  Feature vector shape: {feature_values.shape}")

    if feature_values.shape[1] == 0:
        feature_values = np.random.randn(1, 20)
        feature_names = [f"feature_{i}" for i in range(20)]
        print(f"  Using random features for demo: {feature_names}")

    print("\n  Training models...")

    iforest = IsolationForestModel()
    normal_data = np.random.randn(100, len(feature_names)) * 0.5
    iforest.train(normal_data, feature_names)
    print("    [OK] Isolation Forest trained")

    autoencoder = AutoencoderModel()
    autoencoder.train(normal_data, feature_names)
    print("    [OK] Autoencoder trained")

    xgboost = XGBoostModel()
    labels = np.concatenate([np.zeros(100), np.ones(100)]).flatten()
    combined_data = np.vstack(
        [normal_data, np.random.randn(100, len(feature_names)) * 2]
    )
    xgboost.train(combined_data, labels, feature_names)
    print("    [OK] XGBoost trained")

    print("\n  Running detection on test data...")
    iforest_scores, _ = iforest.predict(feature_values)
    ae_scores, _ = autoencoder.predict(feature_values)
    xgb_scores, _ = xgboost.predict(feature_values)

    print(f"\n  Detection Results:")
    print(f"    Isolation Forest Score: {iforest_scores[0]:.4f}")
    print(f"    Autoencoder Score:      {ae_scores[0]:.4f}")
    print(f"    XGBoost Score:          {xgb_scores[0]:.4f}")

    ensemble = EnsembleDetector()
    ensemble.add_model(iforest)
    ensemble.add_model(autoencoder)
    ensemble.add_model(xgboost)

    return {
        "iforest_score": float(iforest_scores[0]),
        "ae_score": float(ae_scores[0]),
        "xgb_score": float(xgb_scores[0]),
        "feature_names": feature_names,
    }


def demonstrate_explainable_ai(features: dict, ml_results: dict) -> None:
    """Demonstrate explainable AI"""
    print_header("Explainable AI (SHAP/LIME)")

    feature_names = ml_results.get("feature_names", list(features.keys())[:20])
    feature_values = np.array([[features.get(f, 0) for f in feature_names]])

    if feature_values.shape[1] == 0:
        feature_values = np.random.randn(1, 20)
        feature_names = [f"feature_{i}" for i in range(20)]

    explainer = ExplainableAI(provider="shap")

    print("  Generating explanation for anomaly...")

    mock_model = type(
        "MockModel",
        (),
        {
            "predict": lambda x: np.array([[0.8]]),
            "scaler": type(
                "Scaler",
                (),
                {"transform": lambda s, x: x, "fit_transform": lambda s, x: x},
            )(),
        },
    )()

    explanation = explainer.explain_prediction(
        mock_model, feature_values[0], feature_names
    )

    print(f"\n  Explainer: {explanation['explainer_type']}")
    print(f"\n  Top Contributing Factors:")
    for i, feature in enumerate(explanation["top_features"][:3], 1):
        print(
            f"    {i}. {feature['feature']}: {feature['contribution']:.4f} ({feature['percentage']:.1f}%)"
        )

    print(f"\n  Narrative:")
    print(f"    {explanation['narrative']}")


def demonstrate_graph_analysis() -> None:
    """Demonstrate graph analysis capabilities"""
    print_header("Graph Analysis (Neo4j Integration")

    print("  Graph database features:")
    print("    * Entity relationship mapping")
    print("    * Lateral movement detection")
    print("    * Degree centrality calculation")
    print("    * Shortest path analysis")
    print("    * Clustering coefficient")

    print("\n  Example: Detecting lateral movement")
    print("    User_A -> Server_1 -> Database_1 (normal)")
    print("    User_A -> Server_5 -> Database_2 (potential lateral movement)")

    print("\n  Note: Connect to Neo4j to enable full graph analysis")


def demonstrate_alert_generation(ml_results: dict) -> None:
    """Demonstrate alert generation"""
    print_header("Alert Generation")

    anomaly_score = (
        ml_results.get("iforest_score", 0.5)
        + ml_results.get("ae_score", 0.5)
        + ml_results.get("xgb_score", 0.5)
    ) / 3

    if anomaly_score > 0.5:
        severity = Severity.HIGH
        attack_type = AttackType.UNKNOWN
    else:
        severity = Severity.LOW
        attack_type = AttackType.UNKNOWN

    alert = Alert(
        entity_id="user:john.smith",
        entity_type=EntityType.USER,
        severity=severity,
        attack_type=attack_type,
        confidence=0.85,
        anomaly_score=anomaly_score,
        title=f"Anomalous Behavior Detected - User: john.smith",
        description=f"ML models detected unusual behavior patterns with score {anomaly_score:.2f}",
        explanation=f"Alert triggered due to high frequency of events and unusual access patterns.",
    )

    print(f"  Alert ID:        {alert.alert_id}")
    print(f"  Severity:        {alert.severity.value}")
    print(f"  Anomaly Score:   {alert.anomaly_score:.2f}")
    print(f"  Confidence:      {alert.confidence:.2f}")
    print(f"  Title:           {alert.title}")
    print(f"  Description:     {alert.description[:80]}...")


def demonstrate_feedback_api() -> None:
    """Demonstrate feedback loop API"""
    print_header("Feedback Loop API")

    print("  API Endpoints:")
    print("    POST /api/v1/feedback       - Submit analyst feedback")
    print("    GET  /api/v1/feedback/stats - Get feedback statistics")
    print("    POST /api/v1/retraining/trigger - Trigger model retraining")

    print("\n  Feedback Flow:")
    print("    1. Analyst reviews alert")
    print("    2. Submits feedback (true/false positive)")
    print("    3. System collects feedback")
    print("    4. When enough samples: triggers retraining")
    print("    5. Models updated with new labels")


def main():
    """Run complete demonstration"""
    print("\n" + "=" * 60)
    print("  AEGIS-UEBA - Adaptive Entity Guardian & Intelligent Security")
    print("  Enterprise AI-Driven Security Operations Center Platform")
    print("=" * 60)
    print(f"\n  Version: {settings.app.version}")
    print(f"  Environment: {settings.app.environment}")
    print(f"  Window Sizes: {settings.feature_store.window_sizes}")
    print(f"  ML Models: Isolation Forest, Autoencoder, XGBoost")

    try:
        events, generator = generate_test_events()

        feature_result = demonstrate_feature_extraction(events)

        ml_results = demonstrate_ml_detection(
            feature_result.get("features", {}),
            list(feature_result.get("features", {}).keys())[:20]
            or [f"f_{i}" for i in range(20)],
        )

        demonstrate_explainable_ai(feature_result.get("features", {}), ml_results)

        demonstrate_graph_analysis()

        demonstrate_alert_generation(ml_results)

        demonstrate_feedback_api()

        print_header("Demo Complete")
        print("  AEGIS-UEBA platform demonstration finished successfully!")
        print("\n  Next Steps:")
        print("    1. Connect to Kafka for real-time ingestion")
        print("    2. Connect to Redis for feature storage")
        print("    3. Connect to Neo4j for graph analysis")
        print("    4. Run API: python -m uvicorn aegis.api.main:app --port 8080")
        print("\n")

    except Exception as e:
        print(f"\n  Error during demonstration: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
