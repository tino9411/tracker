from .database import db
from .models import Role

def create_default_roles():
    default_roles = ['admin', 'user']

    for role_name in default_roles:
        # Check if the role already exists
        existing_role = Role.query.filter_by(name=role_name).first()
        if not existing_role:
            # Create and add the new role to the database
            new_role = Role(name=role_name)
            db.session.add(new_role)
    # Commit the changes to the database
    db.session.commit()