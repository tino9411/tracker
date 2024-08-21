from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Table, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, backref
from .database import Base
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


class Event(Base):
    __tablename__ = 'event'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False)
    aggregate_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    aggregate_type = Column(String(100), nullable=False)
    payload = Column(JSONB, nullable=False)
    date_created = Column(DateTime, nullable=False, default=func.now())
    metadata = Column(JSONB, nullable=True)