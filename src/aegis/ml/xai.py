"""Explainable AI - SHAP and LIME integration for model explanations"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import numpy as np

from aegis.core.config import settings

logger = logging.getLogger(__name__)

_SHAP_AVAILABLE = False
_LIME_AVAILABLE = False

try:
    import shap as _shap  # noqa: F401
    _SHAP_AVAILABLE = True
except ImportError:
    pass

try:
    import lime as _lime  # noqa: F401
    _LIME_AVAILABLE = True
except ImportError:
    pass


class BaseExplainer(ABC):
    """Abstract base class for explainability methods"""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def explain(
        self, model: Any, instance: np.ndarray, feature_names: List[str]
    ) -> Dict[str, float]:
        """Explain a single prediction"""
        pass


class SHAPExplainer(BaseExplainer):
    """SHAP (SHapley Additive exPlanations) explainer"""

    def __init__(self):
        super().__init__("shap")
        config = settings.explainable_ai.shap
        self.background_samples = config.background_samples
        self.nsamples = config.nsamples
        self.explainer = None

    def explain(
        self, model: Any, instance: np.ndarray, feature_names: List[str]
    ) -> Dict[str, float]:
        """Explain a single prediction using SHAP"""
        if _SHAP_AVAILABLE:
            import shap
            try:
                if self.explainer is None:
                    if hasattr(model, "predict"):
                        self.explainer = shap.Explainer(model.predict, shap.maskers.Independent(instance))
                    else:
                        self.explainer = shap.Explainer(model)
                shap_values = self.explainer(instance.reshape(1, -1) if instance.ndim == 1 else instance[:1])
                values = shap_values.values
                if hasattr(values, "shape") and values.ndim > 1:
                    values = values[0]
                return dict(zip(feature_names, np.abs(values).tolist()))
            except Exception as e:
                logger.warning(f"SHAP computation failed, using fallback: {e}")

        logger.warning("SHAP explainer using fallback (abs feature values) — install 'shap' for real SHAP values")
        feature_importance = {}
        for i, name in enumerate(feature_names):
            if i < len(instance):
                feature_importance[name] = float(abs(instance[i]))
        return feature_importance


class LIMEExplainer(BaseExplainer):
    """LIME (Local Interpretable Model-agnostic Explanations) explainer"""

    def __init__(self):
        super().__init__("lime")
        config = settings.explainable_ai.lime
        self.num_samples = config.num_samples
        self.num_features = config.num_features

    def explain(
        self, model: Any, instance: np.ndarray, feature_names: List[str]
    ) -> Dict[str, float]:
        """Explain a single prediction using LIME"""
        if _LIME_AVAILABLE:
            import lime.lime_tabular
            try:
                explainer = lime.lime_tabular.LimeTabularExplainer(
                    training_data=instance.reshape(1, -1) if instance.ndim == 1 else instance,
                    feature_names=feature_names,
                    mode="regression",
                )
                exp = explainer.explain_instance(
                    instance.flatten() if instance.ndim > 1 else instance,
                    predict_fn=model.predict if hasattr(model, "predict") else model,
                    num_features=self.num_features,
                )
                return dict(exp.as_list())
            except Exception as e:
                logger.warning(f"LIME computation failed, using fallback: {e}")

        logger.warning("LIME explainer using fallback (abs feature values) — install 'lime' for real LIME values")
        feature_importance = {}
        for i, name in enumerate(feature_names):
            if i < len(instance):
                feature_importance[name] = float(abs(instance[i])) * 0.8
        return feature_importance


class ExplainableAI:
    """Unified interface for explainable AI"""

    def __init__(self, provider: Optional[str] = None):
        if provider is None:
            provider = settings.explainable_ai.provider

        if provider == "shap":
            self.explainer = SHAPExplainer()
        else:
            self.explainer = LIMEExplainer()

        logger.info(f"Using {self.explainer.name} explainer")

    def explain_prediction(
        self, model: Any, instance: np.ndarray, feature_names: List[str]
    ) -> Dict[str, Any]:
        """Generate full explanation for a prediction"""
        feature_importance = self.explainer.explain(model, instance, feature_names)

        sorted_features = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )

        top_features = [
            {
                "feature": name,
                "contribution": score,
                "percentage": score
                / max(sum(feature_importance.values()), 1e-10)
                * 100,
            }
            for name, score in sorted_features[:5]
        ]

        narrative = self._generate_narrative(top_features)

        return {
            "feature_importance": feature_importance,
            "top_features": top_features,
            "narrative": narrative,
            "explainer_type": self.explainer.name,
        }

    def _generate_narrative(self, top_features: List[Dict[str, Any]]) -> str:
        """Generate natural language narrative from feature importance"""
        if not top_features:
            return "Normal behavior detected. No significant anomalies found."

        contributions = []
        for feature in top_features:
            feature_name = feature["feature"]
            percentage = feature["percentage"]

            if percentage > 30:
                contribution = f"highly unusual {feature_name}"
            elif percentage > 15:
                contribution = f"unusual {feature_name}"
            else:
                contribution = f"somewhat unusual {feature_name}"

            contributions.append(contribution)

        if len(contributions) == 1:
            narrative = f"Alert triggered because of {contributions[0]}."
        elif len(contributions) == 2:
            narrative = (
                f"Alert triggered because of {contributions[0]} and {contributions[1]}."
            )
        else:
            narrative = (
                f"Alert triggered due to multiple factors: "
                f"{', '.join(contributions[:-1])}, and {contributions[-1]}."
            )

        return narrative

    def explain_alert(
        self,
        anomaly_score: float,
        entity_info: Dict[str, Any],
        feature_importance: Dict[str, float],
    ) -> str:
        """Generate human-readable alert explanation"""
        if anomaly_score < 0.3:
            return (
                f"Low risk alert for {entity_info.get('entity_id', 'unknown')}. "
                f"Behavior is mostly normal with minor deviations."
            )

        top_contributors = sorted(
            feature_importance.items(), key=lambda x: x[1], reverse=True
        )[:3]

        factors = []
        for feature, score in top_contributors:
            if score > 0.1:
                formatted_feature = feature.replace("_", " ").title()
                factors.append(f"{formatted_feature} (score: {score:.2f})")

        if not factors:
            return (
                f"Medium risk alert for {entity_info.get('entity_id', 'unknown')}. "
                f"Multiple minor deviations detected."
            )

        return (
            f"Alert for {entity_info.get('entity_id', 'unknown')} "
            f"(Risk Score: {anomaly_score:.2f}). "
            f"Key factors: {', '.join(factors)}."
        )
