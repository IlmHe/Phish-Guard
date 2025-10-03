# Icon Optimization Guide

## Current Issue

All three extension icons are **identical 29KB files**, which wastes bandwidth and violates Chrome Web Store best practices.

```
icon16.png:  29KB  (should be 1-2KB)
icon48.png:  29KB  (should be 5-10KB)
icon128.png: 29KB  (acceptable)
```

## How to Fix

### Option 1: Using ImageMagick (Recommended)

```bash
# Install ImageMagick
sudo apt-get install imagemagick

# Run the optimization script
./scripts/optimize-icons.sh
```

### Option 2: Using Online Tools

1. Go to https://tinypng.com/ or https://squoosh.app/
2. Upload `src/icons/icon128.png`
3. Resize and download:
   - **icon16.png**: Resize to 16x16, quality 85%
   - **icon48.png**: Resize to 48x48, quality 90%
   - **icon128.png**: Keep at 128x128, optimize quality 92%
4. Replace files in `src/icons/`

### Option 3: Using Photoshop/GIMP

1. Open `src/icons/icon128.png`
2. Create 3 versions:
   - **16x16**: Save for Web, PNG-8, 85% quality
   - **48x48**: Save for Web, PNG-24, 90% quality
   - **128x128**: Save for Web, PNG-24, 92% quality
3. Replace in `src/icons/`

## Verify Optimization

After optimizing, check file sizes:

```bash
ls -lh src/icons/
```

**Expected output:**
```
icon16.png:   ~1-2KB
icon48.png:   ~5-10KB
icon128.png:  ~20-30KB
```

## Why This Matters

1. **Store Requirements**: Chrome Web Store expects properly sized icons
2. **Performance**: Smaller files = faster extension loading
3. **Bandwidth**: Saves user's data when downloading extension
4. **Professionalism**: Shows attention to detail

## Status

⚠️ **Action Required**: Icons need to be optimized before store submission!