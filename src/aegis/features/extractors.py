"""Feature Extractors - Extract behavioral features from events"""

import logging
import math
import hashlib
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aegis.core.models import NormalizedEvent, FeatureVector

logger = logging.getLogger(__name__)


class BaseFeatureExtractor(ABC):
    """Base class for feature extractors"""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        """Extract features from events within the time window"""
        pass

    @abstractmethod
    def get_feature_names(self) -> List[str]:
        """Get names of features this extractor produces"""
        pass


class FrequencyExtractor(BaseFeatureExtractor):
    """Extract frequency-based features"""

    def __init__(self):
        super().__init__("frequency")
        self._feature_names = [
            "login_count",
            "unique_hosts",
            "unique_ips",
            "failed_logins",
            "successful_logins",
            "file_access_count",
            "process_count",
            "dns_query_count",
            "network_connections",
            "avg_events_per_hour",
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names

    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        if not events:
            return {name: 0.0 for name in self._feature_names}

        features = {}
        features["login_count"] = sum(1 for e in events if "login" in e.event_type.lower())
        features["unique_hosts"] = len(set(e.hostname for e in events if e.hostname))
        features["unique_ips"] = len(set(e.source_ip for e in events if e.source_ip))
        features["failed_logins"] = sum(1 for e in events if "failure" in e.event_type.lower())
        features["successful_logins"] = sum(1 for e in events if "success" in e.event_type.lower())
        features["file_access_count"] = sum(1 for e in events if "file" in e.event_type.lower())
        features["process_count"] = sum(1 for e in events if "process" in e.event_type.lower())
        features["dns_query_count"] = sum(1 for e in events if "dns" in e.event_type.lower())
        features["network_connections"] = sum(
            1 for e in events if "network" in e.event_type.lower()
        )

        hours = window_seconds / 3600.0
        total_events = len(events)
        features["avg_events_per_hour"] = total_events / max(hours, 0.1)

        return features


class EntropyExtractor(BaseFeatureExtractor):
    """Extract entropy-based features using Shannon entropy"""

    def __init__(self):
        super().__init__("entropy")
        self._feature_names = [
            "source_ip_entropy",
            "hostname_entropy",
            "event_type_entropy",
            "command_entropy",
            "dns_query_entropy",
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names

    def _shannon_entropy(self, data: List[str]) -> float:
        if not data:
            return 0.0

        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counter.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        if not events:
            return {name: 0.0 for name in self._feature_names}

        features = {}
        features["source_ip_entropy"] = self._shannon_entropy(
            [e.source_ip for e in events if e.source_ip]
        )
        features["hostname_entropy"] = self._shannon_entropy(
            [e.hostname for e in events if e.hostname]
        )
        features["event_type_entropy"] = self._shannon_entropy([e.event_type for e in events])
        features["command_entropy"] = self._shannon_entropy(
            [e.command_line for e in events if e.command_line]
        )
        features["dns_query_entropy"] = self._shannon_entropy(
            [e.dns_query for e in events if e.dns_query]
        )

        return features


class GeoSpatialExtractor(BaseFeatureExtractor):
    """Extract geo-spatial features"""

    def __init__(self):
        super().__init__("geospatial")
        self._feature_names = [
            "unique_countries",
            "unique_cities",
            "max_distance_km",
            "avg_distance_km",
            "velocity_score",
            "impossible_travel_count",
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names

    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        if not events:
            return {name: 0.0 for name in self._feature_names}

        features = {}
        locations = [
            (e.location.get("lat", 0), e.location.get("lon", 0)) for e in events if e.location
        ]

        features["unique_countries"] = len(set(e.country for e in events if e.country))
        features["unique_cities"] = len(set(e.city for e in events if e.city))

        if len(locations) < 2:
            features["max_distance_km"] = 0.0
            features["avg_distance_km"] = 0.0
            features["velocity_score"] = 0.0
            features["impossible_travel_count"] = 0
            return features

        distances = []
        for i in range(1, len(locations)):
            dist = self._haversine_distance(
                locations[i - 1][0], locations[i - 1][1], locations[i][0], locations[i][1]
            )
            distances.append(dist)

        features["max_distance_km"] = max(distances)
        features["avg_distance_km"] = sum(distances) / len(distances)

        total_time = window_seconds
        max_velocity = features["max_distance_km"] / max(total_time / 3600, 0.1)
        features["velocity_score"] = min(max_velocity / 1000, 1.0)

        impossible_travel = sum(
            1
            for d in distances
            if d / max((events[i].timestamp - events[i - 1].timestamp).total_seconds() / 3600, 0.1)
            > 1000
        )
        features["impossible_travel_count"] = impossible_travel

        return features


class TimeSeriesExtractor(BaseFeatureExtractor):
    """Extract time-series based features"""

    def __init__(self):
        super().__init__("timeseries")
        self._feature_names = [
            "events_per_minute",
            "events_per_hour",
            "night_activity_ratio",
            "weekend_activity_ratio",
            "periodicity_score",
            "burst_score",
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names

    def _calculate_periodicity(self, timestamps: List[datetime]) -> float:
        if len(timestamps) < 10:
            return 0.0

        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if delta > 0:
                intervals.append(delta)

        if not intervals:
            return 0.0

        intervals_arr = np.array(intervals)
        mean_interval = np.mean(intervals_arr)
        std_interval = np.std(intervals_arr)

        if mean_interval > 0:
            cv = std_interval / mean_interval
            return max(0, 1 - min(cv, 1))
        return 0.0

    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        if not events:
            return {name: 0.0 for name in self._feature_names}

        features = {}
        timestamps = sorted([e.timestamp for e in events])
        minutes = window_seconds / 60.0
        hours = window_seconds / 3600.0

        features["events_per_minute"] = len(events) / max(minutes, 0.1)
        features["events_per_hour"] = len(events) / max(hours, 0.1)

        night_events = sum(1 for ts in timestamps if ts.hour >= 22 or ts.hour < 6)
        features["night_activity_ratio"] = night_events / len(events)

        weekend_events = sum(1 for ts in timestamps if ts.weekday() >= 5)
        features["weekend_activity_ratio"] = weekend_events / len(events)

        features["periodicity_score"] = self._calculate_periodicity(timestamps)

        event_rate = len(events) / max(window_seconds, 1)
        features["burst_score"] = min(event_rate / 10, 1.0)

        return features


class GraphExtractor(BaseFeatureExtractor):
    """Extract graph-based features from entity relationships"""

    def __init__(self):
        super().__init__("graph")
        self._feature_names = [
            "degree_centrality",
            "betweenness_centrality",
            "clustering_coefficient",
            "new_connections",
            "connection_diversity",
            "access_pattern_score",
        ]

    def get_feature_names(self) -> List[str]:
        return self._feature_names

    def extract(self, events: List[NormalizedEvent], window_seconds: int) -> Dict[str, float]:
        if not events:
            return {name: 0.0 for name in self._feature_names}

        features = {}
        unique_targets = set()
        unique_sources = set()
        connections = []

        for e in events:
            if e.source_ip:
                unique_sources.add(e.source_ip)
            if e.hostname:
                unique_targets.add(e.hostname)
                if e.source_ip:
                    connections.append((e.source_ip, e.hostname))

        total_nodes = len(unique_sources) + len(unique_targets)
        total_possible = total_nodes * (total_nodes - 1) / 2 if total_nodes > 1 else 1

        features["degree_centrality"] = len(connections) / max(total_possible, 1)

        features["betweenness_centrality"] = len(unique_targets) / max(len(unique_sources), 1)

        if len(connections) < 2:
            features["clustering_coefficient"] = 0.0
        else:
            edges_set = set(connections)
            triangles = 0
            for i in range(len(connections)):
                for j in range(i + 1, len(connections)):
                    if (
                        connections[i][0] == connections[j][1]
                        and connections[i][1] == connections[j][0]
                    ):
                        triangles += 1
            features["clustering_coefficient"] = triangles / max(len(connections), 1)

        features["new_connections"] = len(unique_targets)

        features["connection_diversity"] = len(unique_targets) / max(len(connections), 1)

        access_pattern = sum(
            1
            for e in events
            if "delete" in e.event_type.lower() or "modify" in e.event_type.lower()
        )
        features["access_pattern_score"] = access_pattern / max(len(events), 1)

        return features
