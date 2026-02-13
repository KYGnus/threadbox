FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies and Python 3.12
RUN apt-get update && apt-get install -y \
    software-properties-common \
    wget curl unzip git \
    tshark tcpdump \
    build-essential automake autoconf libtool \
    libssl-dev libcurl4-openssl-dev \
    libjson-c-dev libpcre3-dev libyara-dev \
    clamav clamav-daemon clamav-freshclam \
    yara \
    && add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update \
    && apt-get install -y python3.12 python3.12-dev python3.12-distutils python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.12 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1

WORKDIR /app

# Copy application
COPY . .

# Install Maldet (Linux Malware Detect)
RUN cd /tmp && \
    wget http://www.rfxn.com/downloads/maldetect-current.tar.gz && \
    tar -xzf maldetect-current.tar.gz && \
    cd maldetect-* && \
    ./install.sh && \
    cd / && rm -rf /tmp/maldetect-* && \
    # Update maldet signatures
    /usr/local/maldetect/maldet --update-ver || true && \
    /usr/local/maldetect/maldet --update || true

# Install additional YARA rules
RUN mkdir -p /app/ioc_rules/yara && \
    # Clone community YARA rules (shallow clone to save space)
    git clone --depth 1 https://github.com/Yara-Rules/rules.git /tmp/yara-rules && \
    cp /tmp/yara-rules/malware/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    cp /tmp/yara-rules/antidebug_antivm/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    cp /tmp/yara-rules/capabilities/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    cp /tmp/yara-rules/crypto/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    cp /tmp/yara-rules/packers/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    cp /tmp/yara-rules/webshells/*.yar /app/ioc_rules/yara/ 2>/dev/null || true && \
    rm -rf /tmp/yara-rules

# Install FLARE-floss and CAPA
RUN cd /tmp && \
    # Install FLOSS from source
    git clone --depth 1 https://github.com/mandiant/flare-floss.git && \
    cd flare-floss && \
    python3.12 -m pip install --no-cache-dir . && \
    cp scripts/floss /usr/local/bin/ && \
    cd / && rm -rf /tmp/flare-floss && \
    # Install CAPA
    wget -qO /usr/local/bin/capa https://github.com/mandiant/capa/releases/latest/download/capa-linux && \
    chmod +x /usr/local/bin/capa

# Upgrade pip and install Python dependencies
RUN python3.12 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3.12 -m pip install --no-cache-dir -r requirements.txt && \
    python3.12 -m pip install --no-cache-dir -r app/scripts_requirements.txt

# Create necessary directories
RUN mkdir -p /app/uploads /app/scan_results /app/ioc_rules/yara /app/MALDET_TEMP && \
    chmod 777 /app/uploads /app/scan_results /app/ioc_rules/yara /app/MALDET_TEMP

# Configure ClamAV
RUN cp /etc/clamav/clamd.conf.sample /etc/clamav/clamd.conf && \
    cp /etc/clamav/freshclam.conf.sample /etc/clamav/freshclam.conf && \
    sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf && \
    sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 127.0.0.1" >> /etc/clamav/clamd.conf && \
    echo "User root" >> /etc/clamav/clamd.conf && \
    # Update clamav databases
    freshclam --verbose || true

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "═══════════════════════════════════════════"\n\
echo "     🚀 clamNET - Security Platform        "\n\
echo "═══════════════════════════════════════════"\n\
echo ""\n\
\n\
# Update ClamAV databases\n\
echo "[1/5] 📡 Updating ClamAV virus definitions..."\n\
freshclam --daemon-notify 2>/dev/null &\n\
\n\
# Start ClamAV daemon\n\
echo "[2/5] 🛡️ Starting ClamAV daemon..."\n\
if [ -f /etc/clamav/clamd.conf ]; then\n\
    clamd --config-file /etc/clamav/clamd.conf 2>/dev/null &\n\
fi\n\
\n\
# Update Maldet\n\
echo "[3/5] 🔬 Updating Maldet signatures..."\n\
if [ -f /usr/local/maldetect/maldet ]; then\n\
    /usr/local/maldetect/maldet --update 2>/dev/null || true\n\
fi\n\
\n\
# Wait for services\n\
echo "[4/5] ⏳ Initializing services..."\n\
sleep 5\n\
\n\
# Start the Flask application\n\
echo "[5/5] 🌐 Starting web interface on port 5005..."\n\
echo ""\n\
echo "═══════════════════════════════════════════"\n\
echo "     🌐 Web interface: http://localhost:5005"\n\
echo "     📊 Status: ONLINE"\n\
echo "═══════════════════════════════════════════"\n\
echo ""\n\
\n\
cd /app/app && python3.12 main.py\n\
' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 5005

CMD ["/app/start.sh"]