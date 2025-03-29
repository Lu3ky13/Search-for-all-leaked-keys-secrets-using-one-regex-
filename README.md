# Search for All Leaked Keys & Secrets Using One Regex

This repository contains a comprehensive collection of regular expressions to detect sensitive information, API keys, tokens, and credentials in code or text files.

## Complete Regex Patterns Collection

### API Keys & Tokens

| Provider | Pattern | Description |
|----------|---------|-------------|
| Google API | `AIza[0-9A-Za-z-_]{35}` | Google API keys |
| Google Captcha | `6L[0-9A-Za-z-_]{38}\|^6[0-9a-zA-Z_-]{39}$` | Google reCAPTCHA keys |
| Google OAuth | `ya29\.[0-9A-Za-z\-_]+` | Google OAuth tokens |
| AWS Access Key | `A[SK]IA[0-9A-Z]{16}` | AWS access key IDs |
| AWS MWS Token | `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | Amazon MWS auth tokens |
| Facebook Token | `EAACEdEose0cBA[0-9A-Za-z]+` | Facebook access tokens |
| Mailgun API | `key-[0-9a-zA-Z]{32}` | Mailgun API keys |
| Twilio API | `SK[0-9a-fA-F]{32}` | Twilio API keys |
| Twilio SID | `AC[a-zA-Z0-9_\-]{32}` | Twilio account SIDs |
| Stripe API | `sk_live_[0-9a-zA-Z]{24}` | Stripe standard API keys |

### Authorization Patterns

| Type | Pattern | Description |
|------|---------|-------------|
| Basic Auth | `basic\s*[a-zA-Z0-9=:_\+\/-]+` | Basic authorization headers |
| Bearer Token | `bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+` | Bearer tokens |
| API Key | `api[key\|\s*]+[a-zA-Z0-9_\-]+` | Generic API keys |

### Security Tokens & Credentials

| Type | Pattern | Description |
|------|---------|-------------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | RSA private key header |
| DSA Private Key | `-----BEGIN DSA PRIVATE KEY-----` | DSA private key header |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | EC private key header |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | PGP private key block |
| JWT | `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$` | JSON Web Tokens |
| Bearer JWT | `Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+` | JWT in Authorization header |

### Common Identifiers

| Type | Pattern | Description |
|------|---------|-------------|
| Email | `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,7}` | Email addresses |
| URL | `https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[\w\-._~:/?#\[\]@!$&'()*+,;=]*)?` | URLs |
| IP Address | `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$` | IPv4 addresses |
| UUID | `[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}` | Universally Unique Identifiers |

### Secret Detection

| Pattern | Description |
|---------|-------------|
| `(?:password\|passwd\|pwd\|token\|secret)[=:]\s*['"]?([a-zA-Z0-9_-]+)['"]?` | Detects passwords and secrets in assignments |
| `(?:api[_-]?key\|access[_-]?token\|secret)[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?` | Detects API keys in assignments |

## Usage Examples

### JavaScript Example
```javascript
const sensitivePatterns = [
    /AIza[0-9A-Za-z-_]{35}/, // Google API
    /sk_live_[0-9a-zA-Z]{24}/, // Stripe
    /-----BEGIN RSA PRIVATE KEY-----/
];

function scanText(text) {
    return sensitivePatterns.some(pattern => pattern.test(text));
}
