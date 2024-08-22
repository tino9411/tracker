from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
import json
import os
import logging
from kafka.admin import KafkaAdminClient, NewTopic
from .utils import ingest_event_from_kafka
KAFKA_BROKER_URL = os.getenv('KAFKA_BROKER_URL', 'kafka:9092')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Kafka Admin Client
admin_client = KafkaAdminClient(
    bootstrap_servers=KAFKA_BROKER_URL,
    client_id='event-service'
)

# Define Topics
topics = [
    NewTopic(name="event-source", num_partitions=3, replication_factor=1)
]

# Create topics
def create_topics():
    existing_topics = admin_client.list_topics()
    for topic in topics:
        if topic.name not in existing_topics:
            admin_client.create_topics(topic, validate_only=False)
            logger.info(f"Topic: `{topic.name}` created ")

# Persistent Kafka producer
producer = None

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

consumer = None

async def start_kafka_consumer():
    global consumer
    if consumer is None:
        logger.info("Initializing Kafka consumer...")
        consumer = AIOKafkaConsumer(
            "user-events",
            bootstrap_servers=KAFKA_BROKER_URL,
            group_id="event-service-group"
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

async def consume_events():
    await start_kafka_consumer()
    try:
        async for message in consumer:
            event_data = message.value
            logger.info(f"Received event: {event_data}")
            await ingest_event_from_kafka(event_data)
    finally:
        await stop_kafka_consumer()


async def send_kafka_message(topic="event-source", message=None):
    global producer
    try:
        if producer is None:
            await start_kafka_producer()  # Ensure the producer is started before sending
        
        await producer.send_and_wait(topic, message)
        logger.info(f"Kafka message sent: {message}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Kafka message: {e}")
        return False
    

def check_kafka_health() -> bool:
    """
    Check the health of the Kafka connection.

    Returns:
        bool: True if the Kafka connection is healthy, False otherwise.
    """
    try:
        admin_client.list_topics()  # Attempt to list Kafka topics
        return True
    except Exception as e:
        logger.error(f"Kafka health check failed: {e}")
        return False
    

def get_kafka_metrics() -> dict:
    """
    Retrieve Kafka metrics.

    Returns:
        dict: A dictionary containing Kafka metrics.
    """
    try:
        topics = admin_client.list_topics()
        return {
            "topic_count": len(topics),
        }
    except Exception as e:
        logger.error(f"Failed to retrieve Kafka metrics: {e}")
        return {}