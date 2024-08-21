# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Make port 5100 available to the world outside this container
EXPOSE 5100

# Set the PYTHONPATH
ENV PYTHONPATH=/app

# Define environment variables
ENV QUART_APP=app:create_app
ENV QUART_ENV=production
ENV QUART_RUN_HOST=0.0.0.0
ENV QUART_RUN_PORT=5100

# Run the application
CMD ["python", "run.py"]