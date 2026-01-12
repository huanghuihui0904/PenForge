#!/bin/bash

sudo -v

cleanup() {
  echo "[INFO] Caught Ctrl+C, stopping all processes..."
  kill "$SUDO_REFRESH_PID" 2>/dev/null
  pkill -P $$
  exit 1
}

trap cleanup SIGINT SIGTERM

# Keep refreshing the sudo timestamp in background
while true; do sleep 60; sudo -n true; done 2>/dev/null &
SUDO_REFRESH_PID=$!

# Set to "true" to only setup containers without running attacks
SETUP_ONLY=false
PYTHON_BIN="$(command -v python)"

for cve in \
  CVE-2024-36675 CVE-2024-32964 CVE-2023-37999 CVE-2023-51483 CVE-2024-2359 \
  CVE-2024-2624 CVE-2024-2771 CVE-2024-3234 CVE-2024-3408 CVE-2024-3495 \
  CVE-2024-3552 CVE-2024-4223 CVE-2024-4320 CVE-2024-4323 CVE-2024-4442 \
  CVE-2024-4443 CVE-2024-4701 CVE-2024-5084 CVE-2024-5314 CVE-2024-5315 \
  CVE-2024-5452 CVE-2024-22120 CVE-2024-25641 CVE-2024-30542 CVE-2024-31611 \
  CVE-2024-32167 CVE-2024-32511 CVE-2024-32980 CVE-2024-32986 CVE-2024-34070 \
  CVE-2024-34340 CVE-2024-34359 CVE-2024-34716 CVE-2024-35187 CVE-2024-36412 \
  CVE-2024-36779 CVE-2024-36858 CVE-2024-37388 CVE-2024-37831 CVE-2024-37849
do
  echo "Running $cve..."

  for i in {1..5}; do
    echo "  Run $i for $cve..."
    
    CMD_ARGS=(
      --cve "$cve"
      --difficulty zero_day
      --run-number "$i"
    )
    
    if [ "$SETUP_ONLY" = "true" ]; then
      CMD_ARGS+=(--setup-only)
      echo "  [SETUP ONLY MODE] Only initializing container..."
    fi
    
    sudo -E "$PYTHON_BIN" main_cvebench.py "${CMD_ARGS[@]}"
  
  docker buildx prune -af >/dev/null 2>&1 || true

  done
done
