"""Graph Database Module - Neo4j integration for entity relationships"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from neo4j import GraphDatabase

from aegis.core.config import settings
from aegis.core.models import EntityType

logger = logging.getLogger(__name__)


@dataclass
class NodeProperties:
    """Properties for graph nodes"""

    entity_id: str
    entity_type: EntityType
    name: str
    risk_score: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class EdgeProperties:
    """Properties for graph edges"""

    source_id: str
    target_id: str
    edge_type: str
    weight: float = 1.0
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class GraphDatabaseManager:
    """Neo4j graph database manager for entity relationship analysis"""

    def __init__(self):
        self.config = settings.neo4j
        self.driver: Optional[GraphDatabase.driver] = None

    def _get_driver(self) -> GraphDatabase.driver:
        """Get or create Neo4j driver"""
        if self.driver is None:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password),
                max_connection_lifetime=self.config.max_connection_lifetime,
            )
        return self.driver

    def close(self) -> None:
        """Close database connection"""
        if self.driver:
            self.driver.close()

    def create_node(self, properties: NodeProperties) -> str:
        """Create a node in the graph"""
        with self._get_driver().session() as session:
            result = session.run(
                """
                MERGE (n:Entity {entity_id: $entity_id})
                SET n.entity_type = $entity_type,
                    n.name = $name,
                    n.risk_score = $risk_score,
                    n.first_seen = coalesce(n.first_seen, datetime()),
                    n.last_seen = datetime(),
                    n.metadata = $metadata
                RETURN n.entity_id as id
                """,
                entity_id=properties.entity_id,
                entity_type=properties.entity_type.value,
                name=properties.name,
                risk_score=properties.risk_score,
                metadata=str(properties.metadata) if properties.metadata else "{}",
            )
            return result.single()["id"]

    def create_relationship(self, edge: EdgeProperties) -> bool:
        """Create a relationship between two nodes"""
        with self._get_driver().session() as session:
            try:
                session.run(
                    """
                    MATCH (source:Entity {entity_id: $source_id})
                    MATCH (target:Entity {entity_id: $target_id})
                    MERGE (source)-[r:CONNECTED {type: $edge_type}]->(target)
                    SET r.weight = r.weight + $weight,
                        r.last_seen = datetime(),
                        r.count = coalesce(r.count, 0) + 1
                    """,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    edge_type=edge.edge_type,
                    weight=edge.weight,
                )
                return True
            except Exception as e:
                logger.error(f"Error creating relationship: {e}")
                return False

    def record_access(self, user_id: str, resource_id: str, action: str) -> bool:
        """Record an access event between user and resource"""
        edge = EdgeProperties(
            source_id=user_id,
            target_id=resource_id,
            edge_type=action,
            weight=1.0,
            timestamp=datetime.utcnow(),
        )
        return self.create_relationship(edge)

    def get_node_degree(self, entity_id: str) -> Tuple[int, int]:
        """Get in-degree and out-degree for a node"""
        with self._get_driver().session() as session:
            result = session.run(
                """
                MATCH (n:Entity {entity_id: $entity_id})
                OPTIONAL MATCH (n)-[r]->()
                WITH n, count(r) as out_degree
                OPTIONAL MATCH ()-[r]->(n)
                RETURN out_degree, count(r) as in_degree
                """,
                entity_id=entity_id,
            )
            record = result.single()
            return record["out_degree"], record["in_degree"]

    def get_degree_centrality(self, entity_id: str) -> float:
        """Calculate degree centrality for a node"""
        in_deg, out_deg = self.get_node_degree(entity_id)
        return (in_deg + out_deg) / 2

    def get_neighbors(self, entity_id: str, depth: int = 1) -> List[Dict[str, Any]]:
        """Get neighbors of a node"""
        with self._get_driver().session() as session:
            result = session.run(
                f"""
                MATCH (n:Entity {{entity_id: $entity_id}})-[r*1..{depth}]-(neighbor)
                WHERE neighbor.entity_id <> $entity_id
                RETURN neighbor.entity_id as id,
                       neighbor.entity_type as type,
                       neighbor.name as name,
                       neighbor.risk_score as risk,
                       collect(type(r)) as relationship_types
                LIMIT 50
                """,
                entity_id=entity_id,
            )
            return [dict(record) for record in result]

    def find_shortest_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest path between two entities"""
        with self._get_driver().session() as session:
            result = session.run(
                """
                MATCH (source:Entity {entity_id: $source_id}),
                      (target:Entity {entity_id: $target_id})
                MATCH path = shortestPath((source)-[*]-(target))
                RETURN [node in nodes(path) | node.entity_id] as path,
                       length(path) as length
                LIMIT 1
                """,
                source_id=source_id,
                target_id=target_id,
            )
            record = result.single()
            if record:
                return record["path"]
            return None

    def detect_lateral_movement(self, entity_id: str) -> List[Dict[str, Any]]:
        """Detect potential lateral movement patterns"""
        with self._get_driver().session() as session:
            result = session.run(
                """
                MATCH (n:Entity {entity_id: $entity_id})-[r]->(m)
                WHERE r.count > 5
                RETURN m.entity_id as target,
                       m.name as target_name,
                       m.entity_type as target_type,
                       r.type as relationship,
                       r.count as access_count,
                       m.risk_score as target_risk
                ORDER BY r.count DESC
                LIMIT 20
                """,
                entity_id=entity_id,
            )
            return [dict(record) for record in result]

    def get_cluster_coefficient(self, entity_id: str) -> float:
        """Calculate clustering coefficient for a node"""
        with self._get_driver().session() as session:
            result = session.run(
                """
                MATCH (n:Entity {entity_id: $entity_id})-[r1]-(neighbor1)
                WITH n, collect(distinct neighbor1) as neighbors
                WITH n, neighbors, size(neighbors) as degree
                WHERE degree > 1
                UNWIND neighbors as n1
                UNWIND neighbors as n2
                WITH n, n1, n2
                WHERE id(n1) < id(n2)
                MATCH (n1)-[r]-(n2)
                WITH n, count(r) as triangles, degree
                RETURN triangles * 2.0 / (degree * (degree - 1)) as coefficient
                """,
                entity_id=entity_id,
            )
            record = result.single()
            return record["coefficient"] if record else 0.0

    def update_node_risk_score(self, entity_id: str, new_score: float) -> bool:
        """Update risk score for a node"""
        with self._get_driver().session() as session:
            try:
                session.run(
                    """
                    MATCH (n:Entity {entity_id: $entity_id})
                    SET n.risk_score = $new_score,
                        n.last_seen = datetime()
                    """,
                    entity_id=entity_id,
                    new_score=new_score,
                )
                return True
            except Exception as e:
                logger.error(f"Error updating risk score: {e}")
                return False

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get graph statistics"""
        with self._get_driver().session() as session:
            node_count = session.run("MATCH (n:Entity) RETURN count(n) as count").single()["count"]
            edge_count = session.run(
                "MATCH ()-[r:CONNECTED]->() RETURN count(r) as count"
            ).single()["count"]

            return {
                "node_count": node_count,
                "edge_count": edge_count,
            }

    def health_check(self) -> bool:
        """Check if graph database is healthy"""
        try:
            with self._get_driver().session() as session:
                session.run("RETURN 1")
                return True
        except Exception as e:
            logger.error(f"Graph database health check failed: {e}")
            return False
