---
title: NGINX Usage Guide
description: Using ReDoctor to check NGINX location regexes for ReDoS vulnerabilities
---

# NGINX Usage Guide

NGINX location blocks use PCRE-compatible regular expressions that can be vulnerable to ReDoS attacks. This guide covers how to use ReDoctor effectively for NGINX regex validation.

## NGINX Regex Basics

NGINX supports two types of regex location matching:

```nginx
# Case-sensitive regex (~ modifier)
location ~ ^/api/v[0-9]+/users/.*$ { }

# Case-insensitive regex (~* modifier)
location ~* ^/images/.*\.(jpg|png|gif)$ { }
```

### Typical NGINX Pattern Structure

NGINX patterns usually include **explicit anchors**:

- `^` - Start of the URI path
- `$` - End of the URI path

This is important for ReDoS detection because anchored patterns behave differently than unanchored ones.

## Recommended Configuration

For NGINX regex checking, use the **default `AUTO` mode**:

```python
from redoctor import check, Config

# Default config works well for NGINX
config = Config.default()

# Check NGINX location patterns
patterns = [
    r"^/api/v[0-9]+/.*$",
    r"^/([a-z]+)+/data$",  # Vulnerable!
]

for pattern in patterns:
    result = check(pattern, config=config)
    if result.is_vulnerable:
        print(f"VULNERABLE: {pattern}")
        print(f"  Complexity: {result.complexity}")
        print(f"  Attack: {result.attack_pattern}")
```

## Safe vs Vulnerable Patterns

### Safe NGINX Patterns ✅

```nginx
# Simple alternation
location ~ ^/(login|logout|register)$ { }

# Character classes without nesting
location ~ ^/api/v[0-9]+/users/[0-9]+$ { }

# Single quantifiers (not nested)
location ~ ^/static/.*\.(css|js|png)$ { }

# Optional segments
location ~ ^/api(/v[0-9]+)?/health$ { }
```

### Vulnerable NGINX Patterns ❌

```nginx
# Nested quantifiers - EXPONENTIAL
location ~ ^/([a-z]+)+/data$ { }
#           ^^^^^^^^^ nested + inside group with +

# Overlapping alternatives with quantifiers - EXPONENTIAL
location ~ ^/(a|a+)+$ { }
#           ^^^^^^^ overlapping 'a' patterns

# Complex nested groups - EXPONENTIAL
location ~ ^/api/(([a-z]+/)+)data$ { }
#                ^^^^^^^^^^^ nested quantified groups
```

## Analyzing NGINX Config Files

### Using the CLI

```bash
# Scan an NGINX config file
redoctor scan /etc/nginx/sites-available/mysite.conf

# Scan all NGINX configs
redoctor scan /etc/nginx/ --recursive
```

### Using Python

```python
import re
from pathlib import Path
from redoctor import check, Config

def extract_nginx_patterns(config_path: str) -> list[str]:
    """Extract regex patterns from NGINX config."""
    content = Path(config_path).read_text()
    # Match location ~ or ~* blocks
    pattern = r'location\s+~\*?\s+([^\s{]+)'
    return re.findall(pattern, content)

def check_nginx_config(config_path: str):
    """Check NGINX config for ReDoS vulnerabilities."""
    config = Config.default()
    patterns = extract_nginx_patterns(config_path)

    vulnerabilities = []
    for pattern in patterns:
        result = check(pattern, config=config)
        if result.is_vulnerable:
            vulnerabilities.append({
                'pattern': pattern,
                'complexity': str(result.complexity),
                'attack': result.attack_pattern,
            })

    return vulnerabilities

# Usage
vulns = check_nginx_config('/etc/nginx/sites-available/default')
for v in vulns:
    print(f"Pattern: {v['pattern']}")
    print(f"  Risk: {v['complexity']}")
```

## Match Mode Considerations

### Why AUTO Mode Works for NGINX

NGINX patterns typically have explicit anchors (`^...$`), so:

| Pattern Type | Anchor | AUTO Result | Correct? |
|:-------------|:-------|:------------|:---------|
| `^/api/.*$` | Yes | safe | ✅ |
| `^/([a-z]+)+$` | Yes | exponential | ✅ |
| `/([a-z]+)+` | No | safe | ✅ (partial match) |

### When to Use FULL Mode

Use `MatchMode.FULL` if you're unsure about pattern anchoring or want maximum security:

```python
from redoctor import Config
from redoctor.config import MatchMode

# Conservative mode - flags all potential issues
config = Config(match_mode=MatchMode.FULL)
```

### Don't Use PARTIAL for NGINX

Since NGINX patterns have explicit anchors, `PARTIAL` mode would give incorrect results:

```python
# DON'T do this for NGINX
config = Config(match_mode=MatchMode.PARTIAL)  # Wrong!
```

## Common NGINX ReDoS Patterns

### 1. User-Controlled Path Segments

```nginx
# Vulnerable: attacker controls path after /user/
location ~ ^/user/([a-z]+)+$ { }

# Safe alternative: limit segment length
location ~ ^/user/[a-z]{1,50}$ { }
```

### 2. File Extension Matching

```nginx
# Vulnerable: nested quantifier on extension
location ~ ^/files/(([a-z]+\.)+[a-z]+)$ { }

# Safe alternative: explicit extension list
location ~ ^/files/[a-z]+\.(jpg|png|gif|pdf)$ { }
```

### 3. Query String Handling

```nginx
# If using regex on query strings (via $args), be careful
# Vulnerable pattern in map block:
map $args $is_valid {
    ~^([a-z]+&)+$ 1;  # Nested quantifier!
    default 0;
}

# Safe alternative:
map $args $is_valid {
    ~^[a-z]+(&[a-z]+)*$ 1;  # Non-overlapping
    default 0;
}
```

## Gixy Integration

Gixy can use ReDoctor for an optional deeper ReDoS pass while retaining its
NGINX-specific configuration parsing, reporting, and safe fallback checks. On
RPM-based systems with GetPageSpeed Extras enabled:

```bash
sudo dnf install gixy-deep
gixy --deep /etc/nginx/nginx.conf
```

The `gixy-deep` metapackage adds ReDoctor without making it a hard dependency
of the base Gixy RPM. Pip users can install the equivalent extra with
`pip install 'gixy-ng[deep]'`.

## Best Practices

1. **Always use anchors** (`^...$`) for NGINX locations
2. **Avoid nested quantifiers** (`(a+)+`, `(a*)*`)
3. **Prefer character classes** over complex alternations
4. **Limit repetition** with `{n,m}` instead of `+` or `*`
5. **Use explicit extension lists** instead of catch-all patterns
6. **Test with ReDoctor** before deploying to production

## Integration with CI/CD

```yaml
# GitHub Actions example
- name: Check NGINX configs for ReDoS
  run: |
    pip install redoctor
    redoctor scan nginx/ --format=json > results.json
    if jq -e '.vulnerabilities | length > 0' results.json; then
      echo "ReDoS vulnerabilities found!"
      jq '.vulnerabilities' results.json
      exit 1
    fi
```

## Next Steps

- [Configuration Guide →](configuration.md)
- [Vulnerable Patterns →](vulnerable-patterns.md)
- [Safe Patterns →](safe-patterns.md)
