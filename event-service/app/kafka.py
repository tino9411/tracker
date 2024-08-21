from aiokafka import AIOKafkaProducer
import json
import os
import logging
from kafka.admin import KafkaAdminClient, NewTopic

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