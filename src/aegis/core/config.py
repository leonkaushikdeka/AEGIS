"""AEGIS Configuration Management"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from functools import lru_cache

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class KafkaConfig(BaseModel):
    """Kafka configuration"""

    bootstrap_servers: List[str] = ["localhost:9092"]
    topics: Dict[str, str] = Field(default_factory=dict)
    consumer: Dict[str, Any] = Field(default_factory=dict)
    producer: Dict[str, Any] = Field(default_factory=dict)


class RedisConfig(BaseModel):
    """Redis configuration"""

    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    key_prefix: str = "aegis:"
    session_ttl: int = 3600
    feature_ttl: int = 86400


class ElasticsearchConfig(BaseModel):
    """Elasticsearch configuration"""

    hosts: List[str] = ["http://localhost:9200"]
    index: str = "aegis-logs"
    session: int = 86400
    max_retries: int = 3


class Neo4jConfig(BaseModel):
    """Neo4j graph database configuration"""

    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    max_connection_lifetime: int = 3600


class FeatureStoreConfig(BaseModel):
    """Feature store configuration"""

    window_sizes: List[int] = Field(default_factory=lambda: [3600, 86400, 604800])
    batch_size: int = 1000
    calculation_interval: int = 60


class IsolationForestConfig(BaseModel):
    """Isolation Forest model configuration"""

    contamination: float = 0.01
    n_estimators: int = 200
    max_samples: str = "auto"


class AutoencoderConfig(BaseModel):
    """Autoencoder model configuration"""

    encoding_dim: int = 32
    hidden_layers: List[int] = Field(default_factory=lambda: [128, 64, 32])
    dropout_rate: float = 0.2
    epochs: int = 100
    batch_size: int = 256


class XGBoostConfig(BaseModel):
    """XGBoost model configuration"""

    n_estimators: int = 200
    max_depth: int = 6
    learning_rate: float = 0.1
    objective: str = "binary:logistic"


class GNNConfig(BaseModel):
    """Graph Neural Network configuration"""

    hidden_channels: int = 64
    num_layers: int = 3
    num_heads: int = 4
    dropout: float = 0.2


class ModelsConfig(BaseModel):
    """ML models configuration"""

    isolation_forest: IsolationForestConfig = Field(default_factory=IsolationForestConfig)
    autoencoder: AutoencoderConfig = Field(default_factory=AutoencoderConfig)
    xgboost: XGBoostConfig = Field(default_factory=XGBoostConfig)
    gnn: GNNConfig = Field(default_factory=GNNConfig)


class SHAPConfig(BaseModel):
    """SHAP explainer configuration"""

    background_samples: int = 100
    nsamples: int = 200


class LIMEConfig(BaseModel):
    """LIME explainer configuration"""

    num_samples: int = 1000
    num_features: int = 10


class ExplainableAIConfig(BaseModel):
    """Explainable AI configuration"""

    provider: str = "shap"
    shap: SHAPConfig = Field(default_factory=SHAPConfig)
    lime: LIMEConfig = Field(default_factory=LIMEConfig)


class FeedbackConfig(BaseModel):
    """Feedback loop configuration"""

    api_host: str = "0.0.0.0"
    api_port: int = 8080
    retraining: Dict[str, Any] = Field(
        default_factory=lambda: {
            "schedule": "0 0 * * 0",
            "min_samples": 100,
            "confidence_threshold": 0.95,
        }
    )


class DataGenerationConfig(BaseModel):
    """Synthetic data generation configuration"""

    enabled: bool = True
    events_per_second: int = 1000
    attack_probability: float = 0.02
    users: Dict[str, Any] = Field(
        default_factory=lambda: {
            "count": 100,
            "departments": ["Engineering", "IT", "Finance", "HR", "Sales"],
        }
    )


class AppConfig(BaseModel):
    """Application configuration"""

    name: str = "AEGIS-UEBA"
    version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"


class Settings(BaseModel):
    """Main settings class"""

    app: AppConfig = Field(default_factory=AppConfig)
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    feature_store: FeatureStoreConfig = Field(default_factory=FeatureStoreConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    explainable_ai: ExplainableAIConfig = Field(default_factory=ExplainableAIConfig)
    feedback: FeedbackConfig = Field(default_factory=FeedbackConfig)
    data_generation: DataGenerationConfig = Field(default_factory=DataGenerationConfig)


def load_config(config_path: Optional[str] = None) -> Settings:
    """Load configuration from YAML file"""
    if config_path is None:
        config_path = os.environ.get(
            "AEGIS_CONFIG_PATH", str(Path(__file__).parent.parent.parent / "config.yaml")
        )

    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file, "r") as f:
            config_data = yaml.safe_load(f)
        return Settings(**config_data)
    else:
        return Settings()


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return load_config()


settings = get_settings()
