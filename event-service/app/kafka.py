# kafka.py

import json
import os
import logging
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, ConsumerRebalanceListener
from kafka.admin import KafkaAdminClient, NewTopic
from sqlalchemy.exc import SQLAlchemyError
from .utils import ingest_event_from_kafka

KAFKA_BROKER_URL = os.getenv('KAFKA_BROKER_URL', 'kafka:9092')
EVENT_SERVICE_CONSUMER_GROUP = 'event-service-group'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

admin_client = KafkaAdminClient(
    bootstrap_servers=KAFKA_BROKER_URL,
    client_id='event-service'
)

topics = [
    NewTopic(name="event-source", num_partitions=3, replication_factor=1)
]

def create_topics():
    existing_topics = admin_client.list_topics()
    for topic in topics:
        if topic.name not in existing_topics:
            admin_client.create_topics([topic], validate_only=False)
            logger.info(f"Topic: `{topic.name}` created")

producer = None
consumer = None

async def start_kafka_producer():
    global producer
    if producer is None:
        logger.info("Initializing Kafka producer...")
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BROKER_URL,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await producer.start()
        logger.info("Kafka producer started")
    else:
        logger.info("Kafka producer already initialized.")

async def stop_kafka_producer():
    global producer
    if producer is not None:
        await producer.stop()
        producer = None
        logger.info("Kafka producer stopped")

class RebalanceListener(ConsumerRebalanceListener):
    async def on_partitions_revoked(self, revoked):
        logger.info(f"Partitions revoked: {revoked}")

    async def on_partitions_assigned(self, assigned):
        logger.info(f"Partitions assigned: {assigned}")

async def start_kafka_consumer():
    global consumer
    if consumer is None:
        logger.info("Initializing Kafka consumer...")
        consumer = AIOKafkaConsumer(
            'user-events',
            bootstrap_servers=KAFKA_BROKER_URL,
            group_id=EVENT_SERVICE_CONSUMER_GROUP,
            max_poll_records=100,
            max_poll_interval_ms=300000,  # 5 minutes
            enable_auto_commit=False
        )
        await consumer.start()
        logger.info("Kafka consumer started")
    else:
        logger.info("Kafka consumer already initialized.")

async def stop_kafka_consumer():
    global consumer
    if consumer is not None:
        await consumer.stop()
        consumer = None
        logger.info("Kafka consumer stopped")

async def check_consumer_health():
    if consumer is None or not consumer.assignment():
        logger.warning("Consumer is not assigned to any partitions")
        await stop_kafka_consumer()
        await start_kafka_consumer()
    else:
        logger.info(f"Consumer assigned to partitions: {consumer.assignment()}")

async def consume_events():
    await start_kafka_consumer()
    logger.info("Started consuming events...")
    try:
        while True:
            await check_consumer_health()
            batch = await consumer.getmany(timeout_ms=1000, max_records=100)
            for tp, messages in batch.items():
                logger.info(f"Processing batch of {len(messages)} messages from {tp}")
                for message in messages:
                    try:
                        event_data = json.loads(message.value.decode('utf-8'))
                        await ingest_event_from_kafka(event_data)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in event data: {message.value}")
                    except SQLAlchemyError as e:
                        logger.error(f"Database error while ingesting event: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while ingesting event: {e}")
                        raise  # Re-raise unexpected exceptions
                await consumer.commit({tp: messages[-1].offset + 1})
                logger.info(f"Processed and committed batch of {len(messages)} messages from {tp}")
    except Exception as e:
        logger.error(f"Error during event consumption: {e}")
    finally:
        await stop_kafka_consumer()

async def send_kafka_message(topic="event-source", message=None):
    global producer
    try:
        if producer is None:
            await start_kafka_producer()
        
        await producer.send_and_wait(topic, message)
        logger.info(f"Kafka message sent: {message}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Kafka message: {e}")
        return False

def check_kafka_health() -> bool:
    try:
        admin_client.list_topics()
        return True
    except Exception as e:
        logger.error(f"Kafka health check failed: {e}")
        return False

def get_kafka_metrics() -> dict:
    try:
        topics = admin_client.list_topics()
        return {
            "topic_count": len(topics),
        }
    except Exception as e:
        logger.error(f"Failed to retrieve Kafka metrics: {e}")
        return {}