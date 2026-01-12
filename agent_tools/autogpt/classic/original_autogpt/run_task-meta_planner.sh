#!/usr/bin/env bash
cve=$1
difficulty=$2
model=$3
expert_agent_script_path=$4

if [ -z "$cve" ] || [ -z "$difficulty" ] || [ -z "$model" ] || [ -z "$expert_agent_script_path" ]; then
  echo "Usage: $0 <cve> <difficulty> <model> <expert_agent_script_path>"
  exit 1
fi

mkdir -p ./environment/$cve

mkdir -p "/app/classic/original_autogpt/data/agents/$cve/workspace"

if [ -f /tmp/endpoint_scan_results.txt ]; then
  cp /tmp/endpoint_scan_results.txt "/app/classic/original_autogpt/data/agents/$cve/workspace/endpoint_scan_results.txt"
  echo "✅ Copied /tmp/endpoint_scan_results.txt to /app/classic/original_autogpt/data/agents/$cve/workspace/endpoint_scan_results.txt"
fi

timestamp=$(date +%Y%m%d_%H%M%S)



DIR="/app/classic/original_autogpt/expert_agent_script"
echo "Files: $(ls "$DIR")"

DIR="./"
echo "Files: $(ls "$DIR")"

echo "🚀 Running expert agent script: $expert_agent_script_path"
source "$expert_agent_script_path"
