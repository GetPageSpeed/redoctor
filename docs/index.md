---
title: ReDoctor - Python ReDoS Vulnerability Scanner
description: Protect your Python applications from Regular Expression Denial of Service (ReDoS) attacks with static analysis and intelligent fuzzing.
hide:
  - navigation
---

<div class="hero" markdown>

# :shield: ReDoctor

**The Python ReDoS Vulnerability Scanner**

Protect your applications from Regular Expression Denial of Service attacks
with static analysis and intelligent fuzzing.

<div class="btn-group">
  <a href="getting-started/" class="btn btn-primary">
    :rocket: Get Started
  </a>
  <a href="https://github.com/GetPageSpeed/redoctor" class="btn btn-secondary">
    :fontawesome-brands-github: View on GitHub
  </a>
</div>

</div>

<div class="badges" markdown>

[![PyPI version](https://img.shields.io/pypi/v/redoctor.svg?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/redoctor/)
[![Python versions](https://img.shields.io/pypi/pyversions/redoctor.svg?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/redoctor/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause%20%26%20MIT-blue.svg?style=flat-square)](https://github.com/GetPageSpeed/redoctor/blob/main/LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/GetPageSpeed/redoctor/tests.yml?branch=main&style=flat-square&logo=github&label=tests)](https://github.com/GetPageSpeed/redoctor/actions)

</div>

---

## :warning: What is ReDoS?

**Regular Expression Denial of Service (ReDoS)** is a type of algorithmic complexity attack that exploits the worst-case behavior of regex engines. A vulnerable regex can cause your application to hang for minutes—or even hours—when processing malicious input.

!!! danger "This innocent-looking regex is VULNERABLE!"

    ```python
    import re
    pattern = r"^(a+)+$"

    # This will hang your application:
    re.match(pattern, "a" * 30 + "!")  # Takes exponential time!
    ```

**ReDoctor** detects these vulnerabilities before they reach production.

---

## :zap: Quick Start

<div class="quickstart" markdown>

<div class="quickstart-item" markdown>

#### <span class="step-number">1</span> Install

```bash
pip install redoctor
```

Or install the signed GetPageSpeed RPM on supported RPM-based systems:

```bash
sudo dnf install https://extras.getpagespeed.com/release-latest.rpm
sudo dnf install python3-redoctor
```

On EL7, install `python36-redoctor` with `yum` instead.

</div>

<div class="quickstart-item" markdown>

#### <span class="step-number">2</span> Check

```bash
redoctor '^(a+)+$'
# VULNERABLE: ^(a+)+$ - O(2^n)
```

</div>

<div class="quickstart-item" markdown>

#### <span class="step-number">3</span> Integrate

```python
from redoctor import check

result = check(r"^(a+)+$")
if result.is_vulnerable:
    print(f"Attack: {result.attack}")
```

</div>

</div>

---

## :sparkles: Features

<div class="feature-grid" markdown>

<div class="feature-card" markdown>

### :microscope: Hybrid Analysis Engine

Combines **static automata-based analysis** with **intelligent fuzzing** for comprehensive detection. Catches vulnerabilities that single-approach tools miss.

</div>

<div class="feature-card" markdown>

### :zap: Fast & Zero Dependencies

Pure Python with **no external dependencies**. Runs in milliseconds for most patterns. Compatible with **Python 3.6+**.

</div>

<div class="feature-card" markdown>

### :dart: Accurate Results

Generates **proof-of-concept attack strings** with complexity analysis (`O(n²)`, `O(2ⁿ)`, etc.). Low false-positive rate through recall validation.

</div>

<div class="feature-card" markdown>

### :shield: Source Code Scanning

Scan your entire Python codebase for vulnerable regex patterns. Integrates seamlessly with **CI/CD pipelines**.

</div>

</div>

---

## :bar_chart: Complexity Analysis

ReDoctor classifies vulnerabilities by their time complexity:

| Complexity | Description | Risk Level |
|:-----------|:------------|:-----------|
| `O(n)` | Linear — Safe | :white_check_mark: **Safe** |
| `O(n²)` | Quadratic | :warning: **Moderate** |
| `O(n³)` | Cubic | :warning: **High** |
| `O(2ⁿ)` | Exponential | :x: **Critical** |

---

## :robot: How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     ReDoctor Engine                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐         ┌─────────────────┐           │
│  │   Automaton     │         │     Fuzz        │           │
│  │   Checker       │         │    Checker      │           │
│  │                 │         │                 │           │
│  │  • NFA analysis │         │  • VM execution │           │
│  │  • Witness gen  │         │  • Step counting│           │
│  └────────┬────────┘         └────────┬────────┘           │
│           │                           │                     │
│           └───────────┬───────────────┘                     │
│                       │                                     │
│              ┌────────▼────────┐                            │
│              │ Recall Validator│                            │
│              └────────┬────────┘                            │
│                       │                                     │
│              ┌────────▼────────┐                            │
│              │   Diagnostics   │                            │
│              └─────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

[Learn more about how ReDoctor works →](how-it-works.md)

---

## :rocket: Get Started

<div class="btn-group" markdown>

<a href="getting-started/" class="btn btn-primary">
  :book: Read the Guide
</a>
<a href="api/" class="btn btn-secondary">
  :package: API Reference
</a>
<a href="cli/" class="btn btn-secondary">
  :terminal: CLI Docs
</a>

</div>

---

<div class="stats" markdown>

<div class="stat" markdown>
<span class="stat-value">500+</span>
<span class="stat-label">Tests Passing</span>
</div>

<div class="stat" markdown>
<span class="stat-value">0</span>
<span class="stat-label">Dependencies</span>
</div>

<div class="stat" markdown>
<span class="stat-value">3.6+</span>
<span class="stat-label">Python Version</span>
</div>

<div class="stat" markdown>
<span class="stat-value">&lt;10ms</span>
<span class="stat-label">Typical Analysis</span>
</div>

</div>
