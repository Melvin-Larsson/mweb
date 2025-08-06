#!/bin/bash
export CERT_FILE_PATH="./build/cert.pem"
export PRIVATE_KEY_FILE_PATH="./build/key.pem"
export CONTENT_PATH="./content"

./build/web "$@"
