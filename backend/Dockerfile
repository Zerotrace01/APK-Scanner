# DroidScan — Backend Dockerfile (build context: repo root)
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    android-tools-adb \
    wget unzip curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/         ./
COPY static_analysis/ ./static_analysis/
COPY dynamic_sandbox/ ./dynamic_sandbox/
COPY c2_detection/    ./c2_detection/

RUN mkdir -p uploads reports

EXPOSE 8000
