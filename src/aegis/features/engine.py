"""Feature Engineering Engine - Orchestrates feature extraction"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

from aegis.core.config import settings
from aegis.core.models import NormalizedEvent, FeatureVector
from aegis.features.extractors import (
    FrequencyExtractor,
    EntropyExtractor,
    GeoSpatialExtractor,
    TimeSeriesExtractor,
    GraphExtractor,
)

logger = logging.getLogger(__name__)


class FeatureEngineeringEngine:
    """Orchestrates feature extraction for entity behavior analysis"""

    def __init__(self):
        self.config = settings.feature_store
        self.window_sizes = self.config.window_sizes
        self.extractors = [
            FrequencyExtractor(),
            EntropyExtractor(),
            GeoSpatialExtractor(),
            TimeSeriesExtractor(),
            GraphExtractor(),
        ]
        self.entity_events: Dict[str, List[NormalizedEvent]] = defaultdict(list)
        self._task: Optional[asyncio.Task] = None

    def get_all_feature_names(self) -> List[str]:
        """Get all feature names from all extractors"""
        names = []
        for extractor in self.extractors:
            names.extend(extractor.get_feature_names())
        return names

    def add_event(self, event: NormalizedEvent) -> None:
        """Add event to the entity's event buffer"""
        self.entity_events[event.entity_id].append(event)

    def add_events_batch(self, events: List[NormalizedEvent]) -> None:
        """Add multiple events to their respective entity buffers"""
        for event in events:
            self.add_event(event)

    def get_time_window_events(self, entity_id: str, window_seconds: int) -> List[NormalizedEvent]:
        """Get events for an entity within the specified time window"""
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        events = self.entity_events.get(entity_id, [])
        return [e for e in events if e.timestamp >= cutoff]

    def extract_features(self, entity_id: str, window_seconds: int) -> Dict[str, float]:
        """Extract all features for an entity within the time window"""
        events = self.get_time_window_events(entity_id, window_seconds)
        all_features = {}

        for extractor in self.extractors:
            try:
                features = extractor.extract(events, window_seconds)
                all_features.update(features)
            except Exception as e:
                logger.error(f"Error extracting features with {extractor.name}: {e}")
                extractor_features = {name: 0.0 for name in extractor.get_feature_names()}
                all_features.update(extractor_features)

        return all_features

    def compute_all_window_features(self, entity_id: str) -> Dict[int, Dict[str, float]]:
        """Compute features for all configured window sizes"""
        features_by_window = {}
        for window_size in self.window_sizes:
            features = self.extract_features(entity_id, window_size)
            features_by_window[window_size] = features
        return features_by_window

    def create_feature_vector(self, entity_id: str, window_seconds: int) -> FeatureVector:
        """Create a feature vector for ML model input"""
        features = self.extract_features(entity_id, window_seconds)
        is_valid = len(features) > 0

        return FeatureVector(
            entity_id=entity_id,
            timestamp=datetime.utcnow(),
            window_size=window_seconds,
            features=features,
            is_valid=is_valid,
        )

    def get_flattened_features(self, entity_id: str) -> Dict[str, float]:
        """Get all features flattened across all windows"""
        all_features = {}
        features_by_window = self.compute_all_window_features(entity_id)

        for window_size, features in features_by_window.items():
            window_prefix = f"w{window_size}_"
            for feature_name, value in features.items():
                all_features[f"{window_prefix}{feature_name}"] = value

        return all_features

    def cleanup_old_events(self, max_age_seconds: int = 604800) -> int:
        """Remove events older than max_age_seconds"""
        cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds)
        removed_count = 0

        for entity_id in list(self.entity_events.keys()):
            before_count = len(self.entity_events[entity_id])
            self.entity_events[entity_id] = [
                e for e in self.entity_events[entity_id] if e.timestamp >= cutoff
            ]
            removed_count += before_count - len(self.entity_events[entity_id])

            if not self.entity_events[entity_id]:
                del self.entity_events[entity_id]

        logger.info(f"Cleaned up {removed_count} old events")
        return removed_count

    async def start_background_processing(self) -> None:
        """Start background task for periodic feature calculation"""

        async def periodic_processing():
            while True:
                try:
                    await asyncio.sleep(self.config.calculation_interval)
                    await self._process_all_entities()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in periodic processing: {e}")

        self._task = asyncio.create_task(periodic_processing())

    async def stop_background_processing(self) -> None:
        """Stop background processing task"""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _process_all_entities(self) -> None:
        """Process all entities and compute features"""
        for entity_id in list(self.entity_events.keys()):
            try:
                features = self.get_flattened_features(entity_id)
                logger.debug(f"Computed {len(features)} features for entity {entity_id}")
            except Exception as e:
                logger.error(f"Error processing entity {entity_id}: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "entity_count": len(self.entity_events),
            "total_events": sum(len(events) for events in self.entity_events.values()),
            "window_sizes": self.window_sizes,
            "extractor_count": len(self.extractors),
            "total_features": len(self.get_all_feature_names()),
        }
