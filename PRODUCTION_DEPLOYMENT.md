# Production Deployment Guide - Phish Guard

## Environment Variables Security

### For Chrome Web Store Submission:

**⚠️ CRITICAL**: Never include `.env` files in your Chrome Web Store package!

### Production Build Process:

1. **Set Environment Variables Before Build:**
```bash
# Method 1: Export variables
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-anon-key"
npm run build:chrome

# Method 2: Inline variables
SUPABASE_URL="https://your-project.supabase.co" SUPABASE_KEY="your-anon-key" npm run build:chrome
```

2. **Verify Environment Variables Are Not Exposed:**
```bash
# Check that .env is NOT in the package
unzip -l phish-guard-chrome.zip | grep -i env
# Should return empty (no .env files)

# Check for exposed credentials in built files
grep -r "supabase.co" dist/
# Should only show your intended Supabase URL, not in plain text files
```

### Security Checklist:

- [ ] `.env` files are in `.gitignore` ✅
- [ ] `.env` files are NOT in Chrome Web Store package
- [ ] Environment variables are set during build process
- [ ] No credentials are hardcoded in source files
- [ ] Production builds use environment variables only

### Chrome Web Store Package Creation:

```bash
# Clean build with production environment
rm -rf dist/
SUPABASE_URL="your-url" SUPABASE_KEY="your-key" npm run package:chrome
```

This ensures credentials are embedded in the built extension but not exposed in source files or package uploads.