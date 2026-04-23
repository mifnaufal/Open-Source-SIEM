FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY processor.py .
COPY parsers/ ./parsers/

# Create directories
RUN mkdir -p /app/rules /app/logs

# Run the processor
CMD ["python", "processor.py"]
