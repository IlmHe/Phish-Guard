export interface SuspiciousDomainAnalysis {
  hasSuspiciousChars: boolean;
  hasMixedScripts: boolean;
  hasPunycode: boolean;
  hasExcessiveSubdomains: boolean;
  hasNumberLetterMix: boolean;
  hasLookalikeChars: boolean;
  suspiciousPatterns: string[];
  riskScore: number; // 0-100, higher = more suspicious
  recommendation: 'safe' | 'caution' | 'dangerous';
}

export class HomographDetector {
  // Common lookalike character mappings (Unicode homographs)
  private static readonly LOOKALIKE_CHARS = new Map([
    // Cyrillic to Latin lookalikes (lowercase)
    ['а', 'a'], ['е', 'e'], ['о', 'o'], ['р', 'p'], ['с', 'c'], ['х', 'x'], ['у', 'y'],
    ['і', 'i'], ['ј', 'j'], ['ѕ', 's'], ['ԁ', 'd'], ['ԛ', 'q'], ['һ', 'h'], ['ү', 'y'],
    ['ӏ', 'l'], ['ԝ', 'w'], ['ԍ', 'g'],
    // Cyrillic to Latin lookalikes (uppercase)
    ['А', 'A'], ['В', 'B'], ['Е', 'E'], ['К', 'K'], ['М', 'M'], ['Н', 'H'], ['О', 'O'],
    ['Р', 'P'], ['С', 'C'], ['Т', 'T'], ['У', 'Y'], ['Х', 'X'], ['Ѕ', 'S'], ['І', 'I'],
    ['Ј', 'J'], ['Ү', 'Y'], ['Ԝ', 'W'],
    // Greek to Latin lookalikes (lowercase)
    ['α', 'a'], ['β', 'b'], ['γ', 'y'], ['δ', 'd'], ['ε', 'e'], ['ζ', 'z'], ['η', 'n'],
    ['θ', 'o'], ['ι', 'i'], ['κ', 'k'], ['λ', 'l'], ['μ', 'u'], ['ν', 'v'], ['ξ', 'x'],
    ['ο', 'o'], ['π', 'n'], ['ρ', 'p'], ['σ', 'o'], ['τ', 't'], ['υ', 'u'], ['φ', 'o'],
    ['χ', 'x'], ['ψ', 'y'], ['ω', 'w'], ['ϲ', 'c'], ['ϳ', 'j'], ['ϸ', 'p'],
    // Greek to Latin lookalikes (uppercase)
    ['Α', 'A'], ['Β', 'B'], ['Ε', 'E'], ['Ζ', 'Z'], ['Η', 'H'], ['Ι', 'I'], ['Κ', 'K'],
    ['Μ', 'M'], ['Ν', 'N'], ['Ο', 'O'], ['Ρ', 'P'], ['Τ', 'T'], ['Υ', 'Y'], ['Χ', 'X'],
    ['Ϲ', 'C'],
    // Numbers to letters
    ['0', 'o'], ['1', 'l'], ['3', 'e'], ['4', 'a'], ['5', 's'], ['6', 'g'], ['7', 't'], ['8', 'b'], ['9', 'g'],
    // Special Unicode lookalikes
    ['‒', '-'], ['–', '-'], ['—', '-'], ['―', '-'], ['⁃', '-'], // dashes
    ['․', '.'], ['‥', '..'], ['…', '...'], // dots
    ['ǃ', '!'], ['ⅰ', 'i'], ['ⅼ', 'l'], ['ο', 'o'], ['ѕ', 's'], ['х', 'x'], ['у', 'y'],
    // Latin lookalikes (different code points for same visual)
    ['ℓ', 'l'], ['ℯ', 'e'], ['ℊ', 'g'], ['ℎ', 'h'], ['ℴ', 'o'],
    // Fullwidth characters to ASCII
    ['ａ', 'a'], ['ｂ', 'b'], ['ｃ', 'c'], ['ｄ', 'd'], ['ｅ', 'e'], ['ｆ', 'f'], ['ｇ', 'g'],
    ['ｈ', 'h'], ['ｉ', 'i'], ['ｊ', 'j'], ['ｋ', 'k'], ['ｌ', 'l'], ['ｍ', 'm'], ['ｎ', 'n'],
    ['ｏ', 'o'], ['ｐ', 'p'], ['ｑ', 'q'], ['ｒ', 'r'], ['ｓ', 's'], ['ｔ', 't'], ['ｕ', 'u'],
    ['ｖ', 'v'], ['ｗ', 'w'], ['ｘ', 'x'], ['ｙ', 'y'], ['ｚ', 'z']
  ]);

  // Visual similarity patterns (character combinations that look like other characters)
  private static readonly VISUAL_SIMILARITY_PATTERNS: Array<{ pattern: string; replacements: string[] }> = [
    { pattern: 'rn', replacements: ['m'] },        // rn looks like m (rnicrosoft → microsoft)
    { pattern: 'vv', replacements: ['w'] },        // vv looks like w (vvebsite → website)
    { pattern: 'cl', replacements: ['d'] },        // cl looks like d (cletails → details)
    { pattern: 'ii', replacements: ['u'] },        // ii looks like u (in some fonts)
    { pattern: 'l1', replacements: ['u'] },        // l1 looks like u
    { pattern: '0o', replacements: ['8', 'b'] },   // 0o combinations
    { pattern: 'rr', replacements: ['n'] },        // rr looks like n in some fonts
    { pattern: 'nn', replacements: ['m'] },        // nn looks like m
    { pattern: '13', replacements: ['b'] },        // l3 looks like b
    { pattern: 'oo', replacements: ['w'] },        // oo can look like w in stylized fonts
  ];

  // Popular domains to check against for typosquatting
  private static readonly POPULAR_DOMAINS = [
    // Tech giants & search
    'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
    // Social media
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'tiktok.com',
    'snapchat.com', 'pinterest.com', 'reddit.com', 'discord.com', 'telegram.org',
    'whatsapp.com', 'signal.org', 'mastodon.social',
    // Financial & payment
    'paypal.com', 'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
    'coinbase.com', 'binance.com', 'blockchain.com', 'metamask.io', 'opensea.io',
    'revolut.com', 'wise.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
    // E-commerce
    'ebay.com', 'etsy.com', 'walmart.com', 'target.com', 'bestbuy.com',
    'alibaba.com', 'aliexpress.com', 'shopify.com',
    // Cloud & hosting
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com', 'digitalocean.com',
    'heroku.com', 'vercel.com', 'netlify.com', 'cloudflare.com',
    // Developer & productivity
    'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'npmjs.com',
    'docker.com', 'kubernetes.io', 'ubuntu.com', 'redhat.com',
    // Streaming & entertainment
    'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com', 'hbomax.com',
    'twitch.tv', 'vimeo.com', 'soundcloud.com',
    // Communication & collaboration
    'gmail.com', 'outlook.com', 'protonmail.com', 'yahoo.com', 'icloud.com',
    'slack.com', 'zoom.us', 'teams.microsoft.com', 'dropbox.com', 'drive.google.com',
    'notion.so', 'trello.com', 'asana.com', 'monday.com',
    // Security & VPN
    'nordvpn.com', 'expressvpn.com', 'lastpass.com', 'bitwarden.com', 'dashlane.com',
    '1password.com', 'protonvpn.com',
    // Education & reference
    'wikipedia.org', 'medium.com', 'coursera.org', 'udemy.com', 'khanacademy.org',
    'stackoverflow.com', 'w3schools.com',
    // Government & official
    'irs.gov', 'usa.gov', 'cdc.gov', 'nih.gov', 'usps.com'
  ];

  public static detectSuspiciousDomain(domain: string): SuspiciousDomainAnalysis {
    if (!domain || typeof domain !== 'string') {
      throw new Error('Invalid domain provided');
    }

    // Remove dangerous Unicode characters (RTL override, zero-width, null bytes)
    const sanitizedDomain = domain
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Control characters
      .replace(/[\u200B-\u200D\uFEFF]/g, '') // Zero-width characters
      .replace(/[\u202A-\u202E]/g, ''); // RTL/LTR overrides

    const cleanDomain = sanitizedDomain.toLowerCase().trim();
    const suspiciousPatterns: string[] = [];
    let riskScore = 0;

    // Check for punycode (xn-- prefix)
    const hasPunycode = cleanDomain.includes('xn--');
    if (hasPunycode) {
      suspiciousPatterns.push('punycode_encoding');
      riskScore += 30;
    }

    // Check for mixed scripts
    const hasMixedScripts = this.detectMixedScripts(cleanDomain);
    if (hasMixedScripts) {
      suspiciousPatterns.push('mixed_scripts');
      riskScore += 40;
    }

    // Check for lookalike characters
    const hasLookalikeChars = this.detectLookalikeChars(cleanDomain);
    if (hasLookalikeChars) {
      suspiciousPatterns.push('lookalike_characters');
      riskScore += 35;
    }

    // Check for number-letter mixing patterns
    const hasNumberLetterMix = this.detectNumberLetterMix(cleanDomain);
    if (hasNumberLetterMix) {
      suspiciousPatterns.push('number_letter_substitution');
      riskScore += 25;
    }

    // Check for excessive subdomains
    const hasExcessiveSubdomains = this.detectExcessiveSubdomains(cleanDomain);
    if (hasExcessiveSubdomains) {
      suspiciousPatterns.push('excessive_subdomains');
      riskScore += 20;
    }

    // Check for suspicious character patterns
    const hasSuspiciousChars = this.detectSuspiciousChars(cleanDomain);
    if (hasSuspiciousChars) {
      suspiciousPatterns.push('suspicious_characters');
      riskScore += 15;
    }

    // Check for typosquatting against popular domains
    const typosquattingResult = this.detectTyposquatting(cleanDomain);
    if (typosquattingResult.isTyposquatting) {
      suspiciousPatterns.push(`possible_typosquatting_of_${typosquattingResult.targetDomain}`);
      riskScore += 60; // Increased from 50 - typosquatting is a strong phishing indicator
    }

    // Determine recommendation based on risk score
    let recommendation: 'safe' | 'caution' | 'dangerous';
    if (riskScore >= 60) {
      recommendation = 'dangerous';
    } else if (riskScore >= 30) {
      recommendation = 'caution';
    } else {
      recommendation = 'safe';
    }

    return {
      hasSuspiciousChars,
      hasMixedScripts,
      hasPunycode,
      hasExcessiveSubdomains,
      hasNumberLetterMix,
      hasLookalikeChars,
      suspiciousPatterns,
      riskScore: Math.min(riskScore, 100),
      recommendation
    };
  }

  private static detectMixedScripts(domain: string): boolean {
    const hasLatin = /[a-zA-Z]/.test(domain);
    const hasCyrillic = /[\u0400-\u04FF]/.test(domain);
    const hasGreek = /[\u0370-\u03FF]/.test(domain);
    const hasArabic = /[\u0600-\u06FF]/.test(domain);
    const hasHebrew = /[\u0590-\u05FF]/.test(domain);

    const scriptCount = [hasLatin, hasCyrillic, hasGreek, hasArabic, hasHebrew]
      .filter(Boolean).length;

    return scriptCount > 1;
  }

  private static detectLookalikeChars(domain: string): boolean {
    for (const char of domain) {
      if (this.LOOKALIKE_CHARS.has(char)) {
        return true;
      }
    }
    return false;
  }

  private static detectNumberLetterMix(domain: string): boolean {
    // Look for patterns like g00gle, yah00, micr0soft, etc.
    const suspiciousPatterns = [
      /[0-9]+[a-zA-Z]/,  // Numbers followed by letters
      /[a-zA-Z]+[0-9]/,  // Letters followed by numbers
      /[a-zA-Z][0-9][a-zA-Z]/, // Letter-number-letter pattern
      /[0-9][a-zA-Z][0-9]/ // Number-letter-number pattern
    ];

    return suspiciousPatterns.some(pattern => pattern.test(domain));
  }

  private static detectExcessiveSubdomains(domain: string): boolean {
    // Remove common TLD and count remaining dots
    const withoutTLD = domain.replace(/\.(com|org|net|edu|gov|mil|co\.uk|co\.za|com\.au)$/, '');
    const subdomainCount = (withoutTLD.match(/\./g) || []).length;
    return subdomainCount > 3;
  }

  private static detectSuspiciousChars(domain: string): boolean {
    // Check for unusual characters in domain names
    const suspiciousChars = /[^\w.-]/;
    const hasConsecutiveDashes = /--/;
    const hasLeadingTrailingDash = /^-|-$/;

    return suspiciousChars.test(domain) ||
           hasConsecutiveDashes.test(domain) ||
           hasLeadingTrailingDash.test(domain);
  }

  private static detectTyposquatting(domain: string): { isTyposquatting: boolean; targetDomain?: string } {
    const parts = domain.split('.');
    if (parts.length === 0 || !parts[0]) {
      return { isTyposquatting: false };
    }
    const domainWithoutTLD = parts[0];

    for (const popularDomain of this.POPULAR_DOMAINS) {
      const popularParts = popularDomain.split('.');
      if (popularParts.length === 0 || !popularParts[0]) {
        continue;
      }
      const popularWithoutTLD = popularParts[0];

      // Skip if domains are identical
      if (domainWithoutTLD === popularWithoutTLD) {
        continue;
      }

      // Check for close similarity using Levenshtein distance
      const distance = this.levenshteinDistance(domainWithoutTLD, popularWithoutTLD);
      const similarity = 1 - (distance / Math.max(domainWithoutTLD.length, popularWithoutTLD.length));

      // Typosquatting detection thresholds:
      // - Very similar (>=80%) for shorter domains (4-6 chars) - stricter to avoid false positives
      // - Similar (>=70%) for longer domains (7+ chars) - catches more typos like "rnicrosoft"
      const isShortDomain = popularWithoutTLD.length <= 6;
      const threshold = isShortDomain ? 0.80 : 0.70;

      if (similarity >= threshold && popularWithoutTLD.length >= 4) {
        return { isTyposquatting: true, targetDomain: popularDomain };
      }

      // Check for character substitution with lookalikes
      const normalizedInput = this.normalizeLookalikes(domainWithoutTLD);
      if (normalizedInput === popularWithoutTLD) {
        return { isTyposquatting: true, targetDomain: popularDomain };
      }

      // Check for visual similarity patterns (rn→m, vv→w, etc.)
      const visualVariants = this.generateVisualVariants(domainWithoutTLD);
      for (const variant of visualVariants) {
        if (variant === popularWithoutTLD) {
          return { isTyposquatting: true, targetDomain: popularDomain };
        }
      }
    }

    return { isTyposquatting: false };
  }

  private static levenshteinDistance(str1: string, str2: string): number {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

    for (let i = 0; i <= str1.length; i++) {
      matrix[0][i] = i;
    }

    for (let j = 0; j <= str2.length; j++) {
      matrix[j][0] = j;
    }

    for (let j = 1; j <= str2.length; j++) {
      for (let i = 1; i <= str1.length; i++) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1,     // deletion
          matrix[j - 1][i] + 1,     // insertion
          matrix[j - 1][i - 1] + indicator // substitution
        );
      }
    }

    return matrix[str2.length][str1.length];
  }

  private static normalizeLookalikes(domain: string): string {
    let normalized = domain;
    for (const [lookalike, normal] of this.LOOKALIKE_CHARS) {
      normalized = normalized.replace(new RegExp(lookalike, 'g'), normal);
    }
    return normalized;
  }

  /**
   * Generate visual similarity variants of a domain
   * E.g., "rnicrosoft" -> ["rnicrosoft", "microsoft"] (rn looks like m)
   */
  private static generateVisualVariants(domain: string): string[] {
    const variants = new Set<string>([domain]);

    // Apply each visual similarity pattern
    for (const { pattern, replacements } of this.VISUAL_SIMILARITY_PATTERNS) {
      const regex = new RegExp(pattern, 'g');

      // Check if pattern exists in domain
      if (regex.test(domain)) {
        // Generate variants with each possible replacement
        for (const replacement of replacements) {
          const variant = domain.replace(new RegExp(pattern, 'g'), replacement);
          variants.add(variant);
        }
      }
    }

    return Array.from(variants);
  }

  public static getDetectionSummary(analysis: SuspiciousDomainAnalysis): string {
    if (analysis.riskScore === 0) {
      return 'Domain appears safe with no suspicious patterns detected.';
    }

    const issues = analysis.suspiciousPatterns.join(', ');
    const riskLevel = analysis.recommendation.toUpperCase();

    return `Risk Level: ${riskLevel} (Score: ${analysis.riskScore}/100)\nSuspicious patterns: ${issues}`;
  }
}