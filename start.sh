#!/usr/bin/env bash
set -e

export DISPLAY=:99

Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset &
sleep 1

x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -noxdamage -quiet &
sleep 1

websockify --web=/usr/share/novnc/ 6080 localhost:5900 &
sleep 1

echo "Starting CertAuth GUI..."
python main.py