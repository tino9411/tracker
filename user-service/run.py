import asyncio
from app import create_app

# Run the create_app coroutine and get the Quart app instance
app = asyncio.run(create_app())

if __name__ == "__main__":
    # Run the Quart application
    app.run(host='0.0.0.0', port=5100, debug=True)