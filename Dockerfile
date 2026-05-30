# ==============================================================================
# Jerin's Men's Wear - Secure Containerization Manifest
# Hardened Multi-Stage Dockerfile (Alpine Linux)
# ==============================================================================

# --- Stage 1: Build & Dependency compilation ---
FROM python:3.11-alpine AS builder

# Install system compilation packages
RUN apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev \
    gcc \
    musl-dev

# Setup isolated virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install production dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir \
    flask==2.3.3 \
    bcrypt==4.0.1 \
    pymysql==1.1.0 \
    gunicorn==21.2.0 \
    cryptography==41.0.3

# --- Stage 2: Hardened Secure Runtime environment ---
FROM python:3.11-alpine AS runtime

# Install curl strictly for container healthchecks
RUN apk add --no-cache curl

# Create virtual environment replication
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Establish secure non-privileged system user accounts
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Setup application container pathing
WORKDIR /app

# Transfer application components with correct owner privileges
COPY --chown=appuser:appgroup app.py schema.sql ./

# Setup persistent volume directory for SQLite fallback database
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

# Environment variables for production mode
ENV PORT=5000
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Expose restricted application port bounds
EXPOSE 5000

# Downgrade process permissions to non-privileged user accounts
USER appuser

# Container Healthcheck definitions
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Execute production Gunicorn server binding
CMD ["gunicorn", "--workers=4", "--threads=2", "--bind=0.0.0.0:5000", "app:app"]
