#!/bin/bash
set -eo pipefail

# Generate certificates in shared volume
mkdir -p /secrets
if [[ ! -f /secrets/axum.key || ! -f /secrets/axum.crt ]]; then
    #openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    #    -keyout /secrets/axum.key \
    #    -out /secrets/axum.crt \
    #    -subj "/CN=axum-$(hostname)"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout /secrets/axum.key \
        -out /secrets/axum.crt \
        -subj "/CN=api.your-domain.com" \
        -addext "subjectAltName=DNS:localhost,DNS:api.your-domain.com"
    
    touch /secrets/certs_ready
fi

chmod 0600 /secrets/axum.key
chmod 0644 /secrets/axum.crt

until (timeout 1 bash -c 'cat < /dev/null > /dev/tcp/ollama/11434') &>/dev/null; do
    echo "Waiting for Ollama..."
    sleep 2
done

echo "Starting Axum server..."
exec encipher-server