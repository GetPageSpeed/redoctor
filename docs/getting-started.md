---
title: Getting Started with ReDoctor
description: Learn how to install ReDoctor and start detecting ReDoS vulnerabilities in your Python regex patterns in minutes.
---

# Getting Started

This guide will get you up and running with ReDoctor in under 5 minutes.

## Installation

=== "pip"

    ```bash
    pip install redoctor
    ```

=== "pipx (isolated)"

    ```bash
    pipx install redoctor
    ```

=== "RPM (GetPageSpeed)"

    ```bash
    sudo dnf install https://extras.getpagespeed.com/release-latest.rpm
    sudo dnf install python3-redoctor
    ```

    On EL7, use `sudo yum install python36-redoctor`.

=== "From source"

    ```bash
    git clone https://github.com/GetPageSpeed/redoctor.git
    cd redoctor
    pip install -e .
    ```

!!! info "Requirements"
    - Python 3.6 or higher
    - No external dependencies required

!!! tip "Using ReDoctor through Gixy"
    Install `gixy-deep` to add ReDoctor-backed deep analysis while keeping the
    base Gixy RPM free of a hard ReDoctor dependency:

    ```bash
    sudo dnf install gixy-deep
    gixy --deep /etc/nginx/nginx.conf
    ```

## Your First Check

### Command Line

The quickest way to check a regex pattern:

```bash
redoctor '^(a+)+$'
```

Output:
```
VULNERABLE: ^(a+)+$
  Complexity: O(2^n)
  Attack: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
```

### Python API

```python
from redoctor import check

# Check a regex pattern
result = check(r"^(a+)+$")

# Check the result
print(f"Status: {result.status}")           # Status.VULNERABLE
print(f"Complexity: {result.complexity}")   # O(2^n)
print(f"Is vulnerable: {result.is_vulnerable}")  # True

# Get the attack string
if result.is_vulnerable:
    print(f"Attack: {result.attack}")

    # Get detailed attack pattern
    attack = result.attack_pattern
    print(f"Prefix: {attack.prefix!r}")
    print(f"Pump: {attack.pump!r}")
    print(f"Suffix: {attack.suffix!r}")
```

## Understanding the Results

ReDoctor returns a `Diagnostics` object with the following key properties:

| Property | Type | Description |
|:---------|:-----|:------------|
| `status` | `Status` | `SAFE`, `VULNERABLE`, `UNKNOWN`, or `ERROR` |
| `is_vulnerable` | `bool` | Quick check if pattern is vulnerable |
| `is_safe` | `bool` | Quick check if pattern is safe |
| `complexity` | `Complexity` | Time complexity (`O(n)`, `O(n²)`, `O(2ⁿ)`) |
| `attack` | `str` | Generated attack string |
| `attack_pattern` | `AttackPattern` | Detailed attack structure |
| `hotspot` | `Hotspot` | The vulnerable part of the regex |

## Quick Checks

For simple boolean checks:

```python
from redoctor import is_vulnerable, is_safe

# Check if vulnerable
if is_vulnerable(r"(a|a)*$"):
    print("Don't use this pattern!")

# Check if safe
if is_safe(r"^[a-z]+$"):
    print("This pattern is safe to use")
```

## Checking with Flags

Support for regex flags:

=== "CLI"

    ```bash
    # Ignore case
    redoctor 'pattern' --ignore-case

    # Multiline
    redoctor 'pattern' --multiline

    # Dotall
    redoctor 'pattern' --dotall

    # Combined
    redoctor 'pattern' -i -m -s
    ```

=== "Python"

    ```python
    from redoctor import check
    from redoctor.parser.flags import Flags

    flags = Flags(
        ignore_case=True,
        multiline=True,
        dotall=False
    )

    result = check(r"^hello.*world$", flags=flags)
    ```

## Configuration

Customize the analysis behavior:

```python
from redoctor import check, Config

# Default configuration
config = Config.default()

# Quick mode (faster, less thorough)
config = Config.quick()

# Thorough mode (slower, more comprehensive)
config = Config.thorough()

# Custom configuration
config = Config(
    timeout=30.0,           # Analysis timeout (seconds)
    max_attack_length=4096, # Maximum attack string length
    max_iterations=100000,  # Maximum fuzz iterations
)

result = check(r"pattern", config=config)
```

See the [Configuration Guide](configuration.md) for all options.

## Scanning Source Code

Find vulnerable patterns in your Python codebase:

```python
from redoctor.integrations import scan_file, scan_directory

# Scan a single file
vulnerabilities = scan_file("myapp/validators.py")
for vuln in vulnerabilities:
    print(f"{vuln.file}:{vuln.line} - {vuln.pattern}")

# Scan entire project
for vuln in scan_directory("src/", recursive=True):
    if vuln.is_vulnerable:
        print(f"🚨 {vuln}")
```

See [Source Scanning](source-scanning.md) for more details.

## What's Next?

<div class="feature-grid" markdown>

<div class="feature-card" markdown>

### :terminal: CLI Reference

Learn all command-line options and usage patterns.

[Read CLI Docs →](cli.md)

</div>

<div class="feature-card" markdown>

### :package: Python API

Complete API documentation with examples.

[Read API Docs →](api.md)

</div>

<div class="feature-card" markdown>

### :warning: Vulnerable Patterns

Learn which patterns are dangerous and why.

[See Examples →](vulnerable-patterns.md)

</div>

<div class="feature-card" markdown>

### :robot: How It Works

Understand the analysis engine.

[Learn More →](how-it-works.md)

</div>

</div>
