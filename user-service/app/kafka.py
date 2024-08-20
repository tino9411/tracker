from kafka import KafkaProducer, KafkaConsumer
import os
import json
import logging

KAFKA_BROKER_URL = os.getenv('KAFKA_BROKER_URL', 'kafka:9092')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_kafka_producer():
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER_URL,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )


def get_kafka_consumer(topic):
    return KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BROKER_URL,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='user-service-group'
    )
