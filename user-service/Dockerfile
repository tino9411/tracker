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

# Make port 5000 available to the world outside this container

EXPOSE 5000

# Define enviroment variable

ENV FLASK_APP=app

# Run the application

CMD ["flask", "run", "--host=0.0.0.0"]
