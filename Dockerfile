FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip tshark clamav yara wget unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir -r app/scripts_requirements.txt

# Download tools
RUN wget -qO- https://github.com/mandiant/flare-floss/releases/latest/download/floss-linux.zip | \
    busybox unzip -p - floss > /app/floss && chmod +x /app/floss && \
    wget -qO /app/capa https://github.com/mandiant/capa/releases/latest/download/capa-linux && \
    chmod +x /app/capa

EXPOSE 5005

# Simple CMD without complex entrypoint
CMD freshclam 2>/dev/null; clamd 2>/dev/null & sleep 3; python3 main.py
