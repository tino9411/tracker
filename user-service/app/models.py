from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Table, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, backref
from .database import Base
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Association table for the many-to-many relationship between User and Role
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('user.id'), primary_key=True),
    Column('role_id', UUID(as_uuid=True), ForeignKey('role.id'), primary_key=True)
)

class Role(Base):
    __tablename__ = 'role'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Role {self.name}>"
    

class User(Base):
    __tablename__ = 'user'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    date_created = Column(DateTime, nullable=False, default=func.now())
    last_login_time = Column(DateTime, nullable=True)
    reset_token = Column(String(255), nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    isActive = Column(Boolean, nullable=False, default=True)

    # Relationship to the Role model
    roles = relationship('Role', secondary=user_roles, lazy='subquery',
                         backref=backref('users', lazy=True))

    def __repr__(self):
        return f"<User {self.username}>"
    
    async def has_role(self, role_name, session: AsyncSession):
        """
        Checks if the user has a specific role.
        """
        result = await session.execute(select(Role).where(Role.name == role_name, Role.users.any(id=self.id)))
        role = result.scalars().first()
        return role is not None