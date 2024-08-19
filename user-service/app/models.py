from app.database import db
from sqlalchemy.dialects.postgresql import UUID
import uuid

# Association table for the many-to-many relationship between User and Role
user_roles = db.Table(
    'user_roles',
    db.Column('user_id', UUID(as_uuid=True), db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', UUID(as_uuid=True), db.ForeignKey('role.id'), primary_key=True)
)

class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __reprs__(self):
        return f"<Role {self.name}>"
    

class User(db.Model):
    __tablename__ = 'user'


    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=db.func.now())
    last_login_time = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(255), nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    isActive = db.Column(db.Boolean, nullable=False, default=True)

    # Relationship to the Role model

    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                             backref=db.backref('users', lazy=True))

    def __repr__(self):
        return f"<User {self.username}>"
    
    def has_role(self, role_name):
        """
        Checks if the user has a specific role.
        """
        return any(role.name == role_name for role in self.roles)