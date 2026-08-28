FROM python:3.11-slim

# Install system dependencies required for YARA and PostgreSQL
RUN apt-get update && apt-get install -y --no-install-recommends \
    libyara-dev \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install uv

WORKDIR /app

# Copy the entire application first
COPY . .

# Install dependencies (system-wide in container)
RUN uv pip install --system -e .



# Download the MITRE ATT&CK STIX bundle during build
RUN python scripts/download_mitre_data.py

# Expose FastAPI port
EXPOSE 8000

# Run the FastAPI server
CMD ["uvicorn", "yaratrix.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
