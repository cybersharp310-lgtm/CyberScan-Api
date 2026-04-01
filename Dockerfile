FROM python:3.10-slim

# Install system dependencies (needed for some crypto/DB libraries)
RUN apt-get update && apt-get install -y libpq-dev gcc curl && rm -rf /var/lib/apt/lists/*

# Set up work directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy all project files into the container
COPY . .

# Expose the API port
EXPOSE 8000

# Start Uvicorn Server with WebSockets enabled, bound to all interfaces
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
