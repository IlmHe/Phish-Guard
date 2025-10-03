#!/bin/bash

# Set default browser if not specified
if [ -z "$TARGET_BROWSER" ]; then
    TARGET_BROWSER="firefox"
fi

echo "Building for $TARGET_BROWSER..."

# Clean up any existing background processes
pkill -f "webpack --watch" 2>/dev/null || true

# Set output directory based on browser
if [ "$TARGET_BROWSER" = "chrome" ]; then
    OUTPUT_DIR="dist"
    WEB_EXT_ARGS="--target=chromium"
else
    OUTPUT_DIR="dist"
    WEB_EXT_ARGS=""
fi

# Build first, then start watching
echo "Building extension for $TARGET_BROWSER..."
TARGET_BROWSER=$TARGET_BROWSER npx webpack

if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

echo "Starting webpack in watch mode for $TARGET_BROWSER..."
TARGET_BROWSER=$TARGET_BROWSER npx webpack --watch &
WEBPACK_PID=$!

# Wait a moment for webpack to start
sleep 2

echo "Starting web-ext for $TARGET_BROWSER..."
if [ "$TARGET_BROWSER" = "chrome" ]; then
    npx web-ext run --source-dir $OUTPUT_DIR --target=chromium --reload
else
    npx web-ext run --source-dir $OUTPUT_DIR --reload
fi

# Cleanup webpack when web-ext exits
kill $WEBPACK_PID 2>/dev/null || true