# Phish-Guard

A browser extension I built to catch phishing sites that browsers often miss. It monitors external resources loaded by websites and lets you manually scan suspicious links.

**Note:** This is a personal project - not perfect, but it works! Issues and contributions are welcome.

## Current Features

### **Automatic Resource Monitoring (All Websites)**
*   **External Resource Analysis:** Automatically scans external resources (scripts, iframes, images, stylesheets) loaded by websites
*   **Mixed Content Detection:** Identifies HTTP resources loaded on HTTPS pages
*   **Suspicious Pattern Detection:** Detects IP addresses, free domains (.tk, .ml), and suspicious keywords in external resources only
*   **Dynamic Monitoring:** Continuously monitors for new suspicious external resources added via JavaScript
*   **Security Alerts:** Automatic notifications when pages load high-risk external resources (risk score > 30)
*   **Local Analysis Only:** No external API calls during automatic monitoring - all analysis happens in your browser

### **Manual Scanning Features**
*   **Context Menu Integration:** Right-click on links or selected text to initiate detailed scans
*   **URL Validation & Sanitization:** Robust URL validation and sanitization before processing
*   **Database Check:** Verifies URLs against a Supabase database of known phishing sites (primarily South African sources)
*   **Homograph & Punycode Detection:** Advanced detection of suspicious domains using lookalike characters and mixed scripts
*   **Domain Information:** WHOIS data retrieval for registration details and domain age analysis
*   **Certificate Analysis:** SSL certificate validation and expiration monitoring
*   **Risk Assessment:** Intelligent risk scoring (0-100) with clear recommendations

### **External Links & Local Analysis**
*   **VirusTotal Links:** Direct links to manually check domains on VirusTotal (no API integration)
*   **Site File Access:** Links to robots.txt and Google sitemap searches
*   **Local Threat Intelligence:** Simulated API responses using local pattern analysis (not real external APIs)
*   **Manifest V3 Compatible:** Chrome extension standards compliance
*   **Enhanced Security:** Content Security Policy, input validation, and secure URL handling

## Setup

### What You Need

*   [Node.js](https://nodejs.org/) - grab the LTS version
*   npm (comes with Node.js)
*   **Optional:** Supabase account if you want the phishing database feature (I'm using my own with South African phishing URLs, but you can skip this or set up your own)

### Installation

1.  Clone it:
    ```bash
    git clone https://github.com/IlmHe/Phish-Guard.git
    cd Phish-Guard
    ```

2.  (Optional) Create a `.env` file if you want Supabase phishing database:
    ```dotenv
    SUPABASE_URL="https://your-project.supabase.co"
    SUPABASE_KEY="your-anon-key-here"
    ```
    The extension works without this - you'll just skip the phishing database check.

3.  Install packages:
    ```bash
    npm install
    ```

### Development Mode

Works on both Firefox and Chrome:

**For Firefox:**
```bash
npm run start:firefox
```

**For Chrome:**
```bash
npm run start:chrome
```

These use `web-ext` to run the extension with hot reload - changes update automatically.

### Build for Production

**Chrome:**
```bash
npm run build:chrome
# or package for Web Store:
npm run package:chrome  # creates phish-guard-chrome.zip
```

**Firefox:**
```bash
npm run build:firefox
# or package for Add-on store:
npm run package:firefox  # creates phish-guard-firefox.zip
```

Built files go to `dist/` (Chrome) or `dist-firefox/` (Firefox).

## How It Works

The scanner runs multiple checks and combines them into a risk score (0-100). Here's what it looks for:

### Risk Score Levels

- **0-29**: LOW (probably safe)
- **30-59**: MEDIUM (be careful)
- **60-79**: HIGH (likely sketchy)
- **80-100**: CRITICAL (definitely bad news)

### What Gets Checked

#### 1. **Phishing Database**
- **+80 points**: Found in my phishing database (South African URLs mostly)
- Shows "Found in phishing database" or "Clean"

#### 2. **Homograph/Typosquatting**
Catches fake domains that look real:
- **+60 points**: Similar to popular brands (like "rnicrosoft.com")
- **+40 points**: Mixed scripts (Cyrillic 'а' in "exаmple.com")
- **+35 points**: Lookalike Unicode characters
- **+30 points**: Punycode domains (xn--)

#### 3. **Domain Age**
- **+25 points**: Domain less than 90 days old
- Shows how old the domain is

#### 4. **Certificate Age** ⭐
Catches sketchy patterns browsers miss:
- **+25 points**: Certificate issued <24 hours ago
- **+15 points**: Certificate <7 days old
- **+10 points**: Free CA (Let's Encrypt) on brand new domain
- **Why it matters**: A 2-hour-old domain with a 2-hour-old cert is suspicious, but browsers just show "Secure 🔒"
- Uses Certificate Transparency logs (crt.sh with 15s timeout)

#### 5-9. **Other Checks**
- **+40 points**: IP address as domain
- **+30 points**: Suspicious keywords (verify, security, malware)
- **+25 points**: Sketchy TLDs (.tk, .ml, .click, .download)
- **+20 points**: Too many subdomains or URL shorteners
- **+15 points**: No HTTPS
- And more...

### Two Display Modes

**Simple Mode** - Clean view with the essentials:
- Domain age, HTTPS status, certificate age
- Overall risk level
- Database status
- Resource scan results

**Advanced Mode** - Full breakdown:
- Complete risk analysis with point values
- All detected threats
- Suspicious external resources
- WHOIS data
- Links to VirusTotal, URLScan.io, SSL Labs, etc.

### Limitations (Being Honest)

This doesn't:
- ❌ Download/scan files for malware
- ❌ Run pages in a sandbox
- ❌ Analyze page content/text
- ❌ Track your browsing

Most analysis happens locally in your browser.

## Usage

**Automatic Monitoring** (optional, disabled by default):
- Watches external resources loaded by pages
- Shows alerts for high-risk resources
- All analysis is local (no API calls)
- Check console for logs: `🛡️ Phish Guard: Scan completed`

**Manual Scanning:**
1. Right-click any link or page
2. Select "Scan with Phish-Guard"
3. See results in popup window
4. Toggle Simple/Advanced modes
5. Click links to check on VirusTotal, URLScan.io, etc.

## TODO / Ideas

- Real API integrations (PhishTank, Safe Browsing)
- Better pattern detection
- ML-based detection maybe?
- User reporting for false positives

## Contributing

Found a bug? Have an idea? PRs and issues are welcome! This is my first browser extension so code quality isn't perfect.

## Learn More

I wrote a detailed blog post about everything I learned building Phish-Guard: [What I Learned Building Phish-Guard](https://thecyberproject.fi/posts/what-i-learned-building-phish-guard/)

Covers:
- SSL certificates and Certificate Transparency logs
- Homograph attacks and Unicode detection
- iFrame monitoring and external resource analysis
- Mixed content security implications
- All the mistakes and edge cases I discovered

## License

Phish-Guard is licensed under the GNU Affero General Public License.
