#!/bin/bash
# Script to replace console.log/warn/error with logger utility

echo "🔧 Replacing console statements with logger..."

# Files to update
FILES=(
  "src/background.ts"
  "src/content.ts"
  "src/Popup.tsx"
  "src/alert.ts"
)

for file in "${FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "📝 Processing $file..."

    # Replace console.log with logger.log
    sed -i 's/console\.log(/logger.log(/g' "$file"

    # Replace console.warn with logger.warn
    sed -i 's/console\.warn(/logger.warn(/g' "$file"

    # Replace console.error with logger.error
    sed -i 's/console\.error(/logger.error(/g' "$file"

    # Replace console.debug with logger.debug
    sed -i 's/console\.debug(/logger.debug(/g' "$file"

    echo "✅ Updated $file"
  else
    echo "⚠️  File not found: $file"
  fi
done

echo ""
echo "✅ Console statement replacement complete!"
echo "⚠️  Make sure to add 'import logger from './utils/logger';' to each file!"