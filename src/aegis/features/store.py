"""Feature Store - Persist and retrieve entity features"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import redis

from aegis.core.config import settings
from aegis.core.models import FeatureVector, EntityBehavior

logger = logging.getLogger(__name__)


class FeatureStore:
    """Redis-based feature store for fast feature retrieval"""

    def __init__(self):
        self.config = settings.redis
        self.key_prefix = self.config.key_prefix
        self.feature_ttl = self.config.feature_ttl
        self._client: Optional[redis.Redis] = None

    def _get_client(self) -> redis.Redis:
        """Get or create Redis client"""
        if self._client is None:
            self._client = redis.Redis(
                host=self.config.host,
                port=self.config.port,
                db=self.config.db,
                password=self.config.password,
                decode_responses=True,
            )
        return self._client

    def _make_key(self, entity_id: str, feature_type: str) -> str:
        """Create a Redis key with proper prefix"""
        return f"{self.key_prefix}{feature_type}:{entity_id}"

    def save_feature_vector(self, vector: FeatureVector) -> bool:
        """Save a feature vector to the store"""
        try:
            client = self._get_client()
            key = self._make_key(vector.entity_id, "features")
            data = {
                "entity_id": vector.entity_id,
                "timestamp": vector.timestamp.isoformat(),
                "window_size": vector.window_size,
                "features": vector.features,
                "is_valid": vector.is_valid,
            }
            client.setex(key, self.feature_ttl, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error saving feature vector: {e}")
            return False

    def get_feature_vector(
        self, entity_id: str, window_size: Optional[int] = None
    ) -> Optional[FeatureVector]:
        """Retrieve a feature vector from the store"""
        try:
            client = self._get_client()
            key = self._make_key(entity_id, "features")
            data = client.get(key)

            if data:
                parsed = json.loads(data)
                if window_size is None or parsed.get("window_size") == window_size:
                    return FeatureVector(
                        entity_id=parsed["entity_id"],
                        timestamp=datetime.fromisoformat(parsed["timestamp"]),
                        window_size=parsed["window_size"],
                        features=parsed["features"],
                        is_valid=parsed["is_valid"],
                    )
            return None
        except Exception as e:
            logger.error(f"Error retrieving feature vector: {e}")
            return None

    def save_entity_behavior(self, behavior: EntityBehavior) -> bool:
        """Save entity behavior baseline"""
        try:
            client = self._get_client()
            key = self._make_key(behavior.entity_id, "behavior")
            data = {
                "entity_id": behavior.entity_id,
                "entity_type": behavior.entity_type.value,
                "timestamp": behavior.timestamp.isoformat(),
                "features": behavior.features,
                "confidence": behavior.confidence,
                "baseline_version": behavior.baseline_version,
            }
            client.setex(key, self.feature_ttl, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error saving entity behavior: {e}")
            return False

    def get_entity_behavior(self, entity_id: str) -> Optional[EntityBehavior]:
        """Retrieve entity behavior baseline"""
        try:
            client = self._get_client()
            key = self._make_key(entity_id, "behavior")
            data = client.get(key)

            if data:
                parsed = json.loads(data)
                return EntityBehavior(
                    entity_id=parsed["entity_id"],
                    entity_type=parsed["entity_type"],
                    timestamp=datetime.fromisoformat(parsed["timestamp"]),
                    features=parsed["features"],
                    confidence=parsed["confidence"],
                    baseline_version=parsed["baseline_version"],
                )
            return None
        except Exception as e:
            logger.error(f"Error retrieving entity behavior: {e}")
            return None

    def get_all_entity_ids(self) -> List[str]:
        """Get all entity IDs in the store"""
        try:
            client = self._get_client()
            pattern = f"{self.key_prefix}features:*"
            keys = client.keys(pattern)
            prefix_len = len(f"{self.key_prefix}features:")
            return [key[prefix_len:] for key in keys]
        except Exception as e:
            logger.error(f"Error getting entity IDs: {e}")
            return []

    def save_baseline_features(
        self, entity_id: str, features: Dict[str, float], version: int = 1
    ) -> bool:
        """Save baseline features for cold start problem"""
        try:
            client = self._get_client()
            key = self._make_key(entity_id, "baseline")
            data = {
                "features": features,
                "version": version,
                "updated_at": datetime.utcnow().isoformat(),
            }
            client.setex(key, self.feature_ttl * 7, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False

    def get_population_baseline(self, department: str) -> Optional[Dict[str, float]]:
        """Get population-based baseline for cold start"""
        try:
            client = self._get_client()
            key = f"{self.key_prefix}population_baseline:{department}"
            data = client.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Error getting population baseline: {e}")
            return None

    def update_population_baseline(self, department: str, features: Dict[str, float]) -> bool:
        """Update population baseline for a department"""
        try:
            client = self._get_client()
            key = f"{self.key_prefix}population_baseline:{department}"
            data = {
                "features": features,
                "updated_at": datetime.utcnow().isoformat(),
            }
            client.setex(key, self.feature_ttl * 7, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error updating population baseline: {e}")
            return False

    def save_model_prediction(
        self, entity_id: str, model_name: str, prediction: Dict[str, Any]
    ) -> bool:
        """Save model prediction for later analysis"""
        try:
            client = self._get_client()
            key = self._make_key(entity_id, f"prediction:{model_name}")
            data = {
                **prediction,
                "timestamp": datetime.utcnow().isoformat(),
            }
            client.setex(key, self.feature_ttl, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error saving prediction: {e}")
            return False

    def delete_entity(self, entity_id: str) -> bool:
        """Delete all data for an entity"""
        try:
            client = self._get_client()
            patterns = [f"features:{entity_id}", f"behavior:{entity_id}", f"baseline:{entity_id}"]
            for pattern in patterns:
                key = self._make_key(entity_id, pattern.split(":")[-1])
                client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Error deleting entity: {e}")
            return False

    def health_check(self) -> bool:
        """Check if the feature store is healthy"""
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception as e:
            logger.error(f"Feature store health check failed: {e}")
            return False

    def close(self) -> None:
        """Close Redis connection"""
        if self._client:
            self._client.close()
