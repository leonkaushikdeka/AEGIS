"""Synthetic Data Generator - Generate realistic security events for testing"""

import asyncio
import hashlib
import json
import logging
import random
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from aegis.core.config import settings
from aegis.core.models import EventType, AttackType

logger = logging.getLogger(__name__)


class SyntheticDataGenerator:
    """Generate synthetic security events for testing and demonstration"""

    def __init__(self):
        self.config = settings.data_generation
        self.users = self._generate_users()
        self.hosts = self._generate_hosts()
        self.attack_scenarios = self._create_attack_scenarios()
        self._running = False

    def _generate_users(self) -> List[Dict[str, Any]]:
        """Generate synthetic users"""
        departments = self.config.users.get("departments", ["Engineering"])
        users = []
        user_count = self.config.users.get("count", 100)

        first_names = [
            "John",
            "Jane",
            "Bob",
            "Alice",
            "Charlie",
            "Diana",
            "Eve",
            "Frank",
        ]
        last_names = [
            "Smith",
            "Johnson",
            "Williams",
            "Brown",
            "Jones",
            "Garcia",
            "Miller",
            "Davis",
        ]

        for i in range(user_count):
            first_name = random.choice(first_names)
            last_name = random.choice(last_names)
            username = f"{first_name.lower()}.{last_name.lower()}{i}"

            users.append(
                {
                    "user_id": f"user:{username}",
                    "username": username,
                    "email": f"{username}@company.com",
                    "department": random.choice(departments),
                    "role": random.choice(["engineer", "analyst", "manager", "admin"]),
                    "ip_addresses": self._generate_ip_addresses(),
                    "work_hours": (random.randint(7, 10), random.randint(17, 20)),
                    "risk_profile": random.uniform(0.0, 0.3),
                }
            )

        return users

    def _generate_hosts(self) -> List[Dict[str, Any]]:
        """Generate synthetic hosts"""
        hosts = []
        host_prefixes = ["workstation", "server", "database", "app", "fileserver"]

        for i in range(50):
            host_type = random.choice(host_prefixes)
            hosts.append(
                {
                    "host_id": f"host:{host_type}-{i:03d}",
                    "hostname": f"{host_type}-{i:03d}.company.com",
                    "ip_address": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}",
                    "os": random.choice(["Windows", "Linux", "macOS"]),
                    "department": random.choice(
                        self.config.users.get("departments", ["IT"])
                    ),
                    "criticality": random.uniform(0.1, 0.9),
                }
            )

        return hosts

    def _generate_ip_addresses(self) -> List[str]:
        """Generate IP addresses for a user"""
        return [
            f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}",
            f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}",
        ]

    def _create_attack_scenarios(self) -> List[Dict[str, Any]]:
        """Create attack scenarios for injection"""
        return [
            {
                "name": "Brute Force Attack",
                "probability": 0.02,
                "event_types": [EventType.AUTHENTICATION_FAILURE],
                "duration_seconds": 300,
                "target_user": lambda: random.choice(self.users),
            },
            {
                "name": "Impossible Travel",
                "probability": 0.01,
                "event_types": [EventType.LOGIN],
                "duration_seconds": 60,
                "action": self._create_impossible_travel_event,
            },
            {
                "name": "Data Exfiltration",
                "probability": 0.005,
                "event_types": [EventType.FILE_ACCESS, EventType.DATA_EXFILTRATION],
                "duration_seconds": 600,
                "action": self._create_data_exfiltration_event,
            },
            {
                "name": "Privilege Escalation",
                "probability": 0.01,
                "event_types": [EventType.PRIVILEGE_ESCALATION],
                "duration_seconds": 120,
                "action": self._create_privilege_escalation_event,
            },
        ]

    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return str(uuid4())

    def _generate_timestamp(self, user: Dict[str, Any]) -> datetime:
        """Generate timestamp within user's work hours"""
        now = datetime.utcnow()
        start_hour, end_hour = user["work_hours"]
        hour = random.randint(start_hour, end_hour)
        minute = random.randint(0, 59)
        return now.replace(hour=hour, minute=minute, second=0, microsecond=0)

    def _generate_windows_event(
        self, user: Dict[str, Any], event_type: EventType
    ) -> Dict[str, Any]:
        """Generate Windows event log"""
        return {
            "EventID": random.choice(["4624", "4625", "4648", "4672"]),
            "EventType": event_type.value,
            "Computer": random.choice(self.hosts)["hostname"],
            "TargetUserName": user["username"],
            "SubjectUserName": user["username"],
            "IpAddress": random.choice(user["ip_addresses"]),
            "Message": f"{event_type.value} for {user['username']}",
            "TimeCreated": self._generate_timestamp(user).isoformat(),
        }

    def _generate_linux_event(
        self, user: Dict[str, Any], event_type: EventType
    ) -> Dict[str, Any]:
        """Generate Linux syslog event"""
        return {
            "hostname": random.choice(self.hosts)["hostname"],
            "program": random.choice(["sshd", "sudo", "su"]),
            "timestamp": self._generate_timestamp(user).strftime("%b %d %H:%M:%S"),
            "message": f"{event_type.value}: {user['username']} from {random.choice(user['ip_addresses'])}",
        }

    def _generate_cloudtrail_event(
        self, user: Dict[str, Any], event_type: EventType
    ) -> Dict[str, Any]:
        """Generate AWS CloudTrail event"""
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "userName": user["username"],
                "type": "IAMUser",
            },
            "eventName": random.choice(
                ["AssumeRole", "GetObject", "PutObject", "CreateUser"]
            ),
            "eventSource": random.choice(
                ["sts.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com"]
            ),
            "sourceIPAddress": random.choice(user["ip_addresses"]),
            "eventTime": self._generate_timestamp(user).isoformat(),
        }

    def _create_impossible_travel_event(self) -> Dict[str, Any]:
        """Create an impossible travel event"""
        user = random.choice(self.users)
        locations = [
            {"lat": 40.7128, "lon": -74.0060, "city": "New York"},
            {"lat": 51.5074, "lon": -0.1278, "city": "London"},
        ]
        location = random.choice(locations)

        return {
            "event_type": EventType.LOGIN.value,
            "username": user["username"],
            "source_ip": "203.0.113.50",
            "location": location,
            "city": location["city"],
            "country": "US" if location["city"] == "New York" else "GB",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _create_data_exfiltration_event(self) -> Dict[str, Any]:
        """Create a data exfiltration event"""
        user = random.choice(self.users)
        return {
            "event_type": EventType.DATA_EXFILTRATION.value,
            "username": user["username"],
            "source_ip": random.choice(user["ip_addresses"]),
            "file_path": f"/data/exfil_{random.randint(1000, 9999)}.zip",
            "bytes_transferred": random.randint(1000000, 10000000),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _create_privilege_escalation_event(self) -> Dict[str, Any]:
        """Create a privilege escalation event"""
        user = random.choice(self.users)
        return {
            "event_type": EventType.PRIVILEGE_ESCALATION.value,
            "username": user["username"],
            "source_ip": random.choice(user["ip_addresses"]),
            "old_privileges": "user",
            "new_privileges": "root",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def generate_event(self, source_type: str = "windows") -> Dict[str, Any]:
        """Generate a single synthetic event"""
        user = random.choice(self.users)

        if random.random() < self.config.attack_probability:
            scenario = random.choice(self.attack_scenarios)
            if "action" in scenario:
                return scenario["action"]()

        event_type = random.choice(list(EventType))

        if source_type == "windows":
            return self._generate_windows_event(user, event_type)
        elif source_type == "linux":
            return self._generate_linux_event(user, event_type)
        elif source_type == "cloudtrail":
            return self._generate_cloudtrail_event(user, event_type)
        else:
            return self._generate_windows_event(user, event_type)

    def generate_batch(
        self, count: int, source_type: str = "windows"
    ) -> List[Dict[str, Any]]:
        """Generate a batch of synthetic events"""
        return [self.generate_event(source_type) for _ in range(count)]

    async def stream_events(self, callback, source_type: str = "windows") -> None:
        """Stream events at configured rate"""
        self._running = True
        events_per_second = self.config.events_per_second

        while self._running:
            events = self.generate_batch(events_per_second, source_type)
            for event in events:
                await callback(event)
            await asyncio.sleep(1)

    def stop_streaming(self) -> None:
        """Stop event streaming"""
        self._running = False


def create_sample_events() -> List[Dict[str, Any]]:
    """Create sample events for demonstration"""
    generator = SyntheticDataGenerator()

    events = []

    for _ in range(100):
        events.append(generator.generate_event("windows"))
        events.append(generator.generate_event("linux"))
        events.append(generator.generate_event("cloudtrail"))

    return events
