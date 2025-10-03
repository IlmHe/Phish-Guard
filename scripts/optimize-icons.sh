#!/bin/bash
# Script to optimize extension icons to proper sizes

echo "🎨 Optimizing Phish Guard icons..."

# Check if ImageMagick is installed
if ! command -v convert &> /dev/null; then
    echo "❌ ImageMagick not installed. Installing..."
    sudo apt-get update && sudo apt-get install -y imagemagick
fi

SOURCE_ICON="src/icons/icon128.png"

if [ ! -f "$SOURCE_ICON" ]; then
    echo "❌ Source icon not found: $SOURCE_ICON"
    exit 1
fi

echo "📏 Creating optimized icons from $SOURCE_ICON..."

# Create 16x16 icon (target: 1-2KB)
convert "$SOURCE_ICON" -resize 16x16 -strip -quality 85 "src/icons/icon16.png"
echo "✅ Created icon16.png ($(du -h src/icons/icon16.png | cut -f1))"

# Create 48x48 icon (target: 5-10KB)
convert "$SOURCE_ICON" -resize 48x48 -strip -quality 90 "src/icons/icon48.png"
echo "✅ Created icon48.png ($(du -h src/icons/icon48.png | cut -f1))"

# Optimize 128x128 icon (target: 20-30KB)
convert "$SOURCE_ICON" -strip -quality 92 "src/icons/icon128_optimized.png"
mv "src/icons/icon128_optimized.png" "src/icons/icon128.png"
echo "✅ Optimized icon128.png ($(du -h src/icons/icon128.png | cut -f1))"

echo ""
echo "📊 Final icon sizes:"
ls -lh src/icons/ | grep ".png"

echo ""
echo "✅ Icon optimization complete!"