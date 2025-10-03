# Chrome Web Store Permissions Justification - Phish Guard

## Host Permissions: `"*://*/*"`

### Why This Permission Is Required:

**Core Functionality Dependence:**
Phish Guard provides security analysis of ANY website through two features:

1. **Manual URL Scanning** (Primary Feature - Always Active)
   - User right-clicks and selects "Scan with Phish-Guard" on any link or page
   - Requires access to scan the target URL
   - Performs comprehensive security analysis

2. **Optional Automatic Monitoring** (Secondary Feature - Disabled by Default, Opt-In)
   - User must explicitly enable this feature
   - Monitors pages for suspicious resources when enabled
   - Can be disabled at any time

### How The Permission Is Used:

**Manual Scanning (Always Available):**
- User right-clicks on a link or page and selects "Scan with Phish-Guard"
- Extension needs to access the target URL for analysis
- Performs sitemap discovery, certificate validation, and security checks
- User initiates every scan explicitly
- No automatic data collection unless user enables it

**Optional Automatic Monitoring (Opt-In, OFF by Default):**
- **DISABLED BY DEFAULT** - user must explicitly enable
- When enabled, monitors websites for suspicious external resources
- Analyzes scripts, iframes, images loaded by websites
- Generates security alerts for high-risk resources
- User can disable at any time through extension settings

**Technical Requirements:**
- Cannot predict which domains users will want to scan
- Phishing sites constantly change domains (new TLDs, subdomains)
- Security analysis requires direct access to target websites

**Specific Use Cases:**
```
User scans: https://suspicious-bank-login.example.com
Extension needs access to:
- https://suspicious-bank-login.example.com/robots.txt
- https://suspicious-bank-login.example.com/sitemap.xml
- Certificate validation for suspicious-bank-login.example.com
```

### Alternative Approaches Considered:

**❌ Requesting Individual Domain Permissions:**
- Would require users to grant permission for every scan
- Poor user experience with constant permission prompts
- Defeats the purpose of quick security analysis

**❌ Predefined Domain Lists:**
- Impossible to predict all phishing domains
- Would severely limit extension functionality
- Phishing sites use constantly changing domains

**❌ Server-Side Analysis:**
- Would require sending all user URLs to external servers
- Significant privacy concerns
- Higher latency and dependency on external services

### Security Safeguards In Place:

1. **Opt-In by Default** - Automatic monitoring is DISABLED by default
2. **User Control** - Users explicitly enable automatic monitoring if they want it
3. **Local Analysis Priority** - Most security analysis happens locally in browser
4. **Minimal External Data** - External API calls only for manual scans
5. **Temporary Storage** - Monitoring data stored temporarily in memory, cleared when disabled
6. **Transparent Disclosure** - All data collection fully disclosed in privacy policy
7. **Security Purpose Only** - All monitoring focused solely on security threat detection
8. **No Personal Data** - No collection of personal information, passwords, or form inputs

### Compliance With Store Policies:

- **Single Purpose**: Focused solely on phishing protection
- **User Value**: Clear security benefit justifying broad access
- **Privacy First**: Automatic monitoring opt-in, minimal data collection, full disclosure
- **User Control**: Manual scanning always user-initiated, automatic monitoring requires explicit opt-in
- **Narrow Use of Permissions**: Host permissions used only for:
  - User-initiated manual scans (always)
  - Optional automatic monitoring (only when user enables it)

### Why We Need Broad Host Permissions Despite Opt-In Monitoring:

Even with automatic monitoring disabled by default, we need `*://*/*` because:
1. Users can manually scan ANY URL they encounter (phishing sites use any domain)
2. Cannot predict which domains users will need to scan
3. Phishing sites constantly change domains to evade detection
4. Requesting individual domain permissions would defeat the purpose of quick security analysis

This permission enables Phish Guard to fulfill its core security mission while maintaining user privacy and control through opt-in automatic monitoring.