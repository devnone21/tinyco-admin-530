# syntax=docker/dockerfile:1.6

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application code
COPY main.py conn_security.py dashboard.html ./
COPY static ./static

# Run as non-root
RUN useradd --create-home --uid 1000 app \
    && chown -R app:app /app
USER app

EXPOSE 6008

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "6008"]