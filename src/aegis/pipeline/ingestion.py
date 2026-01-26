"""Data Ingestion Pipeline - High-throughput log ingestion from multiple sources"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional
import hashlib
import re

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError

from aegis.core.config import settings
from aegis.core.models import RawEvent, NormalizedEvent, EventType, EntityType

logger = logging.getLogger(__name__)


class LogNormalizer(ABC):
    """Abstract base class for log normalizers"""

    @abstractmethod
    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """Convert raw log to normalized event"""
        pass

    @abstractmethod
    def can_normalize(self, source_type: str) -> bool:
        """Check if this normalizer can handle the source type"""
        pass


class WindowsEventNormalizer(LogNormalizer):
    """Normalizer for Windows Event Logs"""

    EVENT_CODE_MAP = {
        "4624": EventType.LOGIN,
        "4625": EventType.AUTHENTICATION_FAILURE,
        "4634": EventType.LOGOUT,
        "4648": EventType.LOGIN,
        "4672": EventType.PRIVILEGE_ESCALATION,
        "4688": EventType.PROCESS_CREATE,
        "4663": EventType.FILE_ACCESS,
        "4656": EventType.FILE_ACCESS,
        "4670": EventType.PERMISSION_CHANGE,
    }

    def can_normalize(self, source_type: str) -> bool:
        return source_type == "windows"

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            event_code = str(raw_log.get("EventID", raw_log.get("Event_ID", "")))

            if event_code not in self.EVENT_CODE_MAP:
                return None

            event_type = self.EVENT_CODE_MAP.get(event_code, EventType.LOGIN)

            hostname = raw_log.get("Computer", raw_log.get("Hostname"))
            username = raw_log.get("SubjectUserName", raw_log.get("TargetUserName"))

            source_ip = None
            if "IpAddress" in str(raw_log):
                ip_match = re.search(
                    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", str(raw_log)
                )
                if ip_match:
                    source_ip = ip_match.group(1)

            entity_type_val = EntityType.USER if username else EntityType.HOST
            return NormalizedEvent(
                source_type="windows",
                source_ip=source_ip,
                hostname=hostname,
                username=username,
                event_type=event_type.value,
                raw_data=raw_log,
                raw_message=raw_log.get("Message", ""),
                entity_id=f"{entity_type_val.value}:{username or hostname}",
                entity_type=entity_type_val,
            )
        except Exception as e:
            logger.error(f"Error normalizing Windows event: {e}")
            return None


class LinuxSyslogNormalizer(LogNormalizer):
    """Normalizer for Linux Syslog"""

    SYSLOG_PATTERNS = {
        r"sshd\[\d+\]: Accepted password for (\w+)": EventType.LOGIN,
        r"sshd\[\d+\]: Failed password for (\w+)": EventType.AUTHENTICATION_FAILURE,
        r"sudo: (\w+) : TTY=.* ; COMMAND=(.+)": EventType.PRIVILEGE_ESCALATION,
        r"su: (\w+) to (\w+) on": EventType.PRIVILEGE_ESCALATION,
        r"process\[\d+\]: (.+)": EventType.PROCESS_CREATE,
    }

    def can_normalize(self, source_type: str) -> bool:
        return source_type == "linux"

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            message = raw_log.get("message", raw_log.get("Message", ""))

            for pattern, event_type in self.SYSLOG_PATTERNS.items():
                match = re.search(pattern, message)
                if match:
                    username = match.group(1) if match.lastindex >= 1 else None

                    source_ip = None
                    if "from" in message:
                        ip_match = re.search(
                            r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", message
                        )
                        if ip_match:
                            source_ip = ip_match.group(1)

                    return NormalizedEvent(
                        source_type="linux",
                        source_ip=source_ip,
                        hostname=raw_log.get("hostname"),
                        username=username,
                        event_type=event_type.value,
                        raw_data=raw_log,
                        raw_message=message,
                        entity_id=f"user:{username}"
                        if username
                        else f"host:{raw_log.get('hostname')}",
                        entity_type=EntityType.USER if username else EntityType.HOST,
                    )

            return None
        except Exception as e:
            logger.error(f"Error normalizing Linux syslog: {e}")
            return None


class CloudTrailNormalizer(LogNormalizer):
    """Normalizer for AWS CloudTrail logs"""

    def can_normalize(self, source_type: str) -> bool:
        return source_type == "cloudtrail"

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            event_name = raw_log.get("eventName", "")
            event_source = raw_log.get("eventSource", "")

            if "AssumeRole" in event_name or "GetCallerIdentity" in event_name:
                event_type = EventType.LOGIN
            elif "PutObject" in event_name or "GetObject" in event_name:
                event_type = EventType.FILE_ACCESS
            elif "CreateUser" in event_name or "ModifyDBInstance" in event_name:
                event_type = EventType.CONFIGURATION_CHANGE
            else:
                event_type = EventType.NETWORK_CONNECTION

            username = raw_log.get("userIdentity", {}).get("userName")

            source_ip = raw_log.get("sourceIPAddress")

            return NormalizedEvent(
                source_type="cloudtrail",
                source_ip=source_ip,
                hostname=event_source,
                username=username,
                event_type=event_type.value,
                raw_data=raw_log,
                raw_message=raw_log.get("errorMessage", ""),
                entity_id=f"user:{username}" if username else f"service:{event_source}",
                entity_type=EntityType.USER if username else EntityType.APPLICATION,
            )
        except Exception as e:
            logger.error(f"Error normalizing CloudTrail event: {e}")
            return None


class DNSQueryNormalizer(LogNormalizer):
    """Normalizer for DNS query logs"""

    def can_normalize(self, source_type: str) -> bool:
        return source_type == "dns"

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            query_name = raw_log.get("query_name", raw_log.get("query", ""))
            query_type = raw_log.get("query_type", raw_log.get("type", "A"))

            return NormalizedEvent(
                source_type="dns",
                source_ip=raw_log.get("src_ip"),
                hostname=raw_log.get("hostname"),
                username=raw_log.get("user"),
                event_type=EventType.DNS_QUERY.value,
                raw_data=raw_log,
                raw_message=f"{query_type} {query_name}",
                entity_id=f"host:{raw_log.get('hostname', 'unknown')}",
                entity_type=EntityType.HOST,
                dns_query=query_name,
            )
        except Exception as e:
            logger.error(f"Error normalizing DNS query: {e}")
            return None


class OCSFNormalizer(LogNormalizer):
    """OCSF (Open Cybersecurity Schema) normalizer"""

    def can_normalize(self, source_type: str) -> bool:
        return source_type == "ocsf"

    def normalize(self, raw_log: Dict[str, Any]) -> Optional[NormalizedEvent]:
        try:
            return NormalizedEvent(
                source_type="ocsf",
                source_ip=raw_log.get("src_ip"),
                destination_ip=raw_log.get("dest_ip"),
                hostname=raw_log.get("hostname"),
                username=raw_log.get("user_name"),
                event_type=raw_log.get("activity_name", "unknown"),
                raw_data=raw_log,
                raw_message=raw_log.get("raw_data", ""),
                entity_id=raw_log.get(
                    "entity_id", raw_log.get("user_name", raw_log.get("hostname"))
                ),
                entity_type=EntityType(raw_log.get("entity_type", "user")),
                url=raw_log.get("url"),
                dns_query=raw_log.get("dns_query"),
            )
        except Exception as e:
            logger.error(f"Error normalizing OCSF event: {e}")
            return None


class EventIngestionPipeline:
    """High-throughput event ingestion pipeline"""

    def __init__(self):
        self.kafka_config = settings.kafka
        self.normalizers: List[LogNormalizer] = [
            WindowsEventNormalizer(),
            LinuxSyslogNormalizer(),
            CloudTrailNormalizer(),
            DNSQueryNormalizer(),
            OCSFNormalizer(),
        ]
        self._producer: Optional[KafkaProducer] = None
        self._consumer: Optional[KafkaConsumer] = None

    def _get_producer(self) -> KafkaProducer:
        """Get or create Kafka producer"""
        if self._producer is None:
            self._producer = KafkaProducer(
                bootstrap_servers=self.kafka_config.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks=self.kafka_config.producer.get("acks", "all"),
                retries=self.kafka_config.producer.get("retries", 3),
            )
        return self._producer

    def _get_consumer(self) -> KafkaConsumer:
        """Get or create Kafka consumer"""
        if self._consumer is None:
            self._consumer = KafkaConsumer(
                self.kafka_config.topics.get("raw_logs", "aegis.raw_logs"),
                bootstrap_servers=self.kafka_config.bootstrap_servers,
                group_id=self.kafka_config.consumer.get(
                    "group_id", "aegis-consumer-group"
                ),
                auto_offset_reset=self.kafka_config.consumer.get(
                    "auto_offset_reset", "earliest"
                ),
                enable_auto_commit=self.kafka_config.consumer.get(
                    "enable_auto_commit", True
                ),
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
        return self._consumer

    def get_normalizer(self, source_type: str) -> Optional[LogNormalizer]:
        """Get appropriate normalizer for source type"""
        for normalizer in self.normalizers:
            if normalizer.can_normalize(source_type):
                return normalizer
        return None

    def normalize_event(
        self, raw_log: Dict[str, Any], source_type: str
    ) -> Optional[NormalizedEvent]:
        """Normalize a raw log event"""
        normalizer = self.get_normalizer(source_type)
        if normalizer:
            return normalizer.normalize(raw_log)
        logger.warning(f"No normalizer found for source type: {source_type}")
        return None

    def publish_normalized_event(self, event: NormalizedEvent) -> None:
        """Publish normalized event to Kafka"""
        try:
            producer = self._get_producer()
            topic = self.kafka_config.topics.get("normalized", "aegis.normalized")
            future = producer.send(topic, key=event.entity_id, value=event.model_dump())
            producer.flush()
            logger.debug(f"Published normalized event: {event.event_id}")
        except KafkaError as e:
            logger.error(f"Error publishing event to Kafka: {e}")

    def process_raw_log(
        self, raw_log: Dict[str, Any], source_type: str
    ) -> Optional[NormalizedEvent]:
        """Process a raw log and publish normalized event"""
        normalized = self.normalize_event(raw_log, source_type)
        if normalized:
            self.publish_normalized_event(normalized)
        return normalized

    async def consume_events(self) -> AsyncGenerator[NormalizedEvent, None]:
        """Asynchronously consume and yield normalized events"""
        consumer = self._get_consumer()
        for message in consumer:
            try:
                raw_log = message.value
                source_type = raw_log.get("source_type", "unknown")
                normalized = self.normalize_event(raw_log, source_type)
                if normalized:
                    yield normalized
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    def close(self) -> None:
        """Close Kafka connections"""
        if self._producer:
            self._producer.close()
        if self._consumer:
            self._consumer.close()
