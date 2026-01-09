# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run app.py when the container launches using gunicorn
# Bind to 0.0.0.0:$PORT if PORT is set, otherwise 5000
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
