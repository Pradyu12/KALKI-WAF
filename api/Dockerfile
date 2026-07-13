FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend and frontend
COPY api ./api
COPY dashboard ./dashboard

# Set working directory to the backend folder so imports work correctly
WORKDIR /app/api

EXPOSE 8000

# Use main:app because we are now in /app/api
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]