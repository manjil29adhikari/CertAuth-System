FROM python:3.11-slim
ENV DISPLAY=:99
# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps for Tkinter GUI + VNC/noVNC
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk tk \
    xvfb x11vnc novnc websockify \
    xterm \
    libxext6 libxrender1 libxtst6 libxi6 libx11-6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create a place for runtime DB/certs (optional but helpful)
RUN mkdir -p /app/database /app/certs

# noVNC web port
EXPOSE 6080

# Start virtual display + VNC + noVNC + run app
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]