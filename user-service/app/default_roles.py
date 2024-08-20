from .database import async_session
from .models import Role
from sqlalchemy.future import select

async def create_default_roles(session):
    default_roles = ['admin', 'user']

    async with async_session() as session:
        async with session.begin():
            for role_name in default_roles:
                # Check if the role already exists
                result = await session.execute(
                    select(Role).filter_by(name=role_name)
                )
                existing_role = result.scalars().first()
                if not existing_role:
                    # Create and add the new role to the database
                    new_role = Role(name=role_name)
                    session.add(new_role)
            # Commit the changes to the database
            await session.commit()