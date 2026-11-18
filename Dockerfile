FROM python:3.11-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/data/app.db

# Default command starts the resolver; compose overrides per service.
CMD ["python", "-m", "app.resolver"]
