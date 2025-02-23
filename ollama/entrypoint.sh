#!/bin/sh

# Start Ollama server in background
echo "Starting Ollama server..."
ollama serve &

# Wait for server to initialize
echo "Waiting for server to start..."
for i in $(seq 1 30); do
  if ollama list >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

# Pull model
echo "Pulling model: ${MODEL}"
ollama pull ${MODEL}

# Verify model
echo "Verifying model..."
if ollama ls | grep -q ${MODEL}; then
  echo "Model loaded successfully"
else
  echo "Failed to load model!"
  exit 1
fi

# Keep container running
wait