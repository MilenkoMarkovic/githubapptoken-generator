#!/bin/bash

# Build script for GitHub Action
set -e

echo "Installing dependencies..."
npm ci

echo "Linting code..."
npm run lint

echo "Running tests..."
npm test

echo "Building action..."
npm run build

echo "Build completed successfully!"
echo "The compiled action is available in the 'dist' directory."
