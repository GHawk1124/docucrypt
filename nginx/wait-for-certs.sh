#!/bin/sh
set -e

secret_dir="/etc/nginx/secrets"
max_retries=30
retry_count=0

echo "Waiting for certificates..."
until [ -f "${secret_dir}/axum.crt" ] && [ -f "${secret_dir}/axum.key" ]; do
    if [ $retry_count -ge $max_retries ]; then
        echo "Certificate timeout after ${max_retries} seconds!"
        exit 1
    fi
    retry_count=$((retry_count+1))
    sleep 1
done

echo "Certificates found! Starting Nginx..."
exec nginx -g "daemon off;"

wait