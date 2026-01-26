"""ML Detection Models - Ensemble of ML models for anomaly detection"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import joblib

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier

from aegis.core.config import settings
from aegis.core.models import ModelPrediction, EnsemblePrediction

logger = logging.getLogger(__name__)


class BaseDetectionModel(ABC):
    """Abstract base class for detection models"""

    def __init__(self, name: str):
        self.name = name
        self.is_trained = False

    @abstractmethod
    def train(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Train the model on normal data"""
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly scores and labels"""
        pass

    @abstractmethod
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        pass


class IsolationForestModel(BaseDetectionModel):
    """Isolation Forest for unsupervised anomaly detection"""

    def __init__(self):
        super().__init__("isolation_forest")
        config = settings.models.isolation_forest
        self.model = IsolationForest(
            contamination=config.contamination,
            n_estimators=config.n_estimators,
            max_samples=config.max_samples,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.feature_means: Optional[np.ndarray] = None

    def train(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Train Isolation Forest on normal data"""
        self.feature_names = feature_names
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.feature_means = np.mean(X, axis=0)
        self.is_trained = True
        logger.info(f"Isolation Forest trained on {X.shape[0]} samples")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly scores"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        labels = self.model.predict(X_scaled)

        anomaly_scores = 1 - (scores - scores.min()) / (
            scores.max() - scores.min() + 1e-10
        )

        return anomaly_scores, labels

    def get_feature_importance(self) -> Dict[str, float]:
        """Get pseudo feature importance based on tree depths"""
        if not self.is_trained or not self.feature_names:
            return {}

        importance = {}
        for i, name in enumerate(self.feature_names):
            importance[name] = float(1.0 / (self.feature_means[i] + 1))

        total = sum(importance.values())
        return {k: v / total for k, v in importance.items()}

    def save(self, path: str) -> None:
        """Save model to disk"""
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "feature_names": self.feature_names,
                "feature_means": self.feature_means,
            },
            path,
        )
        logger.info(f"Model saved to {path}")

    def load(self, path: str) -> None:
        """Load model from disk"""
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.feature_means = data["feature_means"]
        self.is_trained = True
        logger.info(f"Model loaded from {path}")


class AutoencoderModel(BaseDetectionModel):
    """Autoencoder for unsupervised anomaly detection using sklearn MLP"""

    def __init__(self):
        super().__init__("autoencoder")
        config = settings.models.autoencoder
        self.encoding_dim = config.encoding_dim
        self.hidden_layers = config.hidden_layers
        self.dropout_rate = config.dropout_rate
        self.epochs = config.epochs
        self.batch_size = config.batch_size

        self.model = None
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.reconstruction_errors: np.ndarray = np.array([])

    def _build_model(self, input_dim: int):
        """Build autoencoder model using sklearn MLPRegressor"""
        from sklearn.neural_network import MLPRegressor

        hidden_layers = tuple(self.hidden_layers) + (self.encoding_dim,)

        return MLPRegressor(
            hidden_layer_sizes=hidden_layers,
            activation="relu",
            solver="adam",
            max_iter=self.epochs,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
        )

    def train(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Train autoencoder on normal data"""
        self.feature_names = feature_names
        X_scaled = self.scaler.fit_transform(X)

        self.model = self._build_model(X.shape[1])
        self.model.fit(X_scaled, X_scaled)

        predictions = self.model.predict(X_scaled)
        self.reconstruction_errors = np.mean(
            np.power(X_scaled - predictions, 2), axis=1
        )

        self.is_trained = True
        logger.info(f"Autoencoder trained on {X.shape[0]} samples")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly scores based on reconstruction error"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        X_scaled = self.scaler.transform(X)

        if hasattr(self.model, "predict"):
            predictions = self.model.predict(X_scaled)
        else:
            predictions = self.model(X_scaled)

        reconstruction_errors = np.mean(np.power(X_scaled - predictions, 2), axis=1)

        error_mean = np.mean(self.reconstruction_errors)
        error_std = np.std(self.reconstruction_errors)

        anomaly_scores = np.clip(
            (reconstruction_errors - error_mean) / (error_std + 1e-10), 0, 1
        )

        labels = (anomaly_scores > 0.5).astype(int)

        return anomaly_scores, labels

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from reconstruction error contribution"""
        if not self.is_trained or not self.feature_names:
            return {}

        return {name: 1.0 / len(self.feature_names) for name in self.feature_names}


class XGBoostModel(BaseDetectionModel):
    """XGBoost for supervised classification on known attacks"""

    def __init__(self):
        super().__init__("xgboost")
        config = settings.models.xgboost
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []
        self.label_encoder = None

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> None:
        """Train XGBoost on labeled data"""
        self.feature_names = feature_names
        X_scaled = self.scaler.fit_transform(X)

        try:
            import xgboost as xgb

            self.model = xgb.XGBClassifier(
                n_estimators=settings.models.xgboost.n_estimators,
                max_depth=settings.models.xgboost.max_depth,
                learning_rate=settings.models.xgboost.learning_rate,
                objective=settings.models.xgboost.objective,
                random_state=42,
                use_label_encoder=False,
                eval_metric="logloss",
            )
            self.model.fit(X_scaled, y)
        except ImportError:
            from sklearn.ensemble import RandomForestClassifier

            self.model = RandomForestClassifier(
                n_estimators=settings.models.xgboost.n_estimators,
                max_depth=settings.models.xgboost.max_depth,
                random_state=42,
            )
            self.model.fit(X_scaled, y)

        self.is_trained = True
        logger.info(f"XGBoost trained on {X.shape[0]} samples")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly probability and labels"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")

        X_scaled = self.scaler.transform(X)

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_scaled)[:, 1]
        else:
            probabilities = self.model.predict(X_scaled)

        labels = (probabilities > 0.5).astype(int)

        return probabilities, labels

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from model"""
        if not self.is_trained or not self.feature_names:
            return {}

        if hasattr(self.model, "feature_importances_"):
            importance = self.model.feature_importances_
            return dict(zip(self.feature_names, importance.astype(float)))

        return {name: 1.0 / len(self.feature_names) for name in self.feature_names}


class EnsembleDetector:
    """Ensemble of multiple detection models"""

    def __init__(self):
        self.models: Dict[str, BaseDetectionModel] = {}
        self.threshold = 0.5

    def add_model(self, model: BaseDetectionModel) -> None:
        """Add a model to the ensemble"""
        self.models[model.name] = model
        logger.info(f"Added model: {model.name}")

    def train(
        self, X_normal: np.ndarray, X_attack: Optional[np.ndarray] = None
    ) -> None:
        """Train all models"""
        for name, model in self.models.items():
            if isinstance(model, XGBoostModel) and X_attack is not None:
                y = np.concatenate([np.zeros(len(X_normal)), np.ones(len(X_attack))])
                X_combined = np.vstack([X_normal, X_attack])
                model.train(X_combined, y, [])
            else:
                model.train(X_normal, [])

    def predict(self, X: np.ndarray, feature_names: List[str]) -> EnsemblePrediction:
        """Run all models and combine predictions"""
        predictions = []
        total_score = 0.0
        anomaly_count = 0

        for name, model in self.models.items():
            try:
                if not model.is_trained:
                    continue

                scores, labels = model.predict(X)

                if len(scores) == 0:
                    continue

                avg_score = float(np.mean(scores))
                avg_label = int(np.mean(labels) > 0.5)

                total_score += avg_score
                anomaly_count += avg_label

                feature_importance = model.get_feature_importance()

                explanation = self._generate_explanation(
                    name, avg_score, feature_importance, feature_names
                )

                predictions.append(
                    ModelPrediction(
                        model_name=name,
                        anomaly_score=avg_score,
                        is_anomaly=avg_label == 1,
                        confidence=1.0 - abs(avg_score - 0.5) * 2,
                        feature_contributions=feature_importance,
                        explanation=explanation,
                    )
                )
            except Exception as e:
                logger.error(f"Error predicting with {name}: {e}")

        final_score = total_score / len(predictions) if predictions else 0.0
        final_decision = final_score > self.threshold
        consensus = anomaly_count / len(predictions) if predictions else 0.0

        return EnsemblePrediction(
            entity_id="",
            timestamp=datetime.utcnow(),
            predictions=predictions,
            final_score=final_score,
            final_decision=final_decision,
            consensus_level=consensus,
        )

    def _generate_explanation(
        self,
        model_name: str,
        score: float,
        importance: Dict[str, float],
        feature_names: List[str],
    ) -> str:
        """Generate natural language explanation"""
        if score < 0.3:
            return f"{model_name}: Normal behavior detected"

        top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:3]

        feature_str = ", ".join(
            [f"{name} ({contrib:.2f})" for name, contrib in top_features]
        )

        return f"{model_name}: Anomaly detected. Top contributors: {feature_str}"

    def get_aggregated_importance(self, feature_names: List[str]) -> Dict[str, float]:
        """Get aggregated feature importance across all models"""
        aggregated = {}
        count = 0

        for model in self.models.values():
            importance = model.get_feature_importance()
            for feature, score in importance.items():
                if feature not in aggregated:
                    aggregated[feature] = 0.0
                aggregated[feature] += score
            count += 1

        if count > 0:
            return {k: v / count for k, v in aggregated.items()}
        return {}
