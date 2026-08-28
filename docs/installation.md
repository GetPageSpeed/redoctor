---
title: Installation Guide
description: Install ReDoctor for ReDoS vulnerability detection. Supports Python 3.6+ with zero dependencies.
---

# Installation

ReDoctor is a pure Python package with no external dependencies, making installation simple and reliable.

## Requirements

- **Python**: 3.6 or higher
- **Dependencies**: None (pure Python)
- **OS**: Linux, macOS, Windows

## Quick Install

=== "pip"

    ```bash
    pip install redoctor
    ```

=== "pip (user)"

    ```bash
    pip install --user redoctor
    ```

=== "pipx"

    ```bash
    # Install pipx first if needed
    pip install pipx

    # Install redoctor in isolated environment
    pipx install redoctor
    ```

=== "RPM (GetPageSpeed)"

    ```bash
    sudo dnf install https://extras.getpagespeed.com/release-latest.rpm
    sudo dnf install python3-redoctor
    ```

    On EL7, use `sudo yum install python36-redoctor`. The packages are signed
    and published through the normal GetPageSpeed Extras repository pipeline.

    For Gixy's optional deep ReDoS mode, install the companion metapackage
    instead. It pulls the correct ReDoctor package for the distribution:

    ```bash
    sudo dnf install gixy-deep
    gixy --deep /etc/nginx/nginx.conf
    ```

## Verify Installation

After installation, verify it works:

=== "CLI"

    ```bash
    redoctor --version
    # ReDoctor 0.1.0
    ```

=== "Python"

    ```python
    import redoctor
    print(redoctor.__version__)
    # 0.1.0
    ```

## Development Installation

For contributing or development:

```bash
# Clone the repository
git clone https://github.com/GetPageSpeed/redoctor.git
cd redoctor

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Verify installation
redoctor --version
python -c "import redoctor; print(redoctor.__version__)"
```

## Upgrading

=== "pip"

    ```bash
    pip install --upgrade redoctor
    ```

=== "pipx"

    ```bash
    pipx upgrade redoctor
    ```

=== "RPM (GetPageSpeed)"

    ```bash
    sudo dnf upgrade python3-redoctor
    ```

    On EL7, upgrade `python36-redoctor` with `yum`.

## Uninstalling

=== "pip"

    ```bash
    pip uninstall redoctor
    ```

=== "pipx"

    ```bash
    pipx uninstall redoctor
    ```

=== "RPM (GetPageSpeed)"

    ```bash
    sudo dnf remove python3-redoctor
    ```

    On EL7, remove `python36-redoctor` with `yum`.

## Virtual Environment Best Practices

We recommend using virtual environments to avoid dependency conflicts:

=== "venv"

    ```bash
    # Create virtual environment
    python -m venv myproject-env

    # Activate
    source myproject-env/bin/activate  # Linux/macOS
    myproject-env\Scripts\activate     # Windows

    # Install
    pip install redoctor
    ```

=== "conda"

    ```bash
    # Create conda environment
    conda create -n myproject python=3.11

    # Activate
    conda activate myproject

    # Install
    pip install redoctor
    ```

## Docker

For containerized environments:

```dockerfile
FROM python:3.11-slim

RUN pip install --no-cache-dir redoctor

ENTRYPOINT ["redoctor"]
```

Build and run:

```bash
docker build -t redoctor .
docker run --rm redoctor '^(a+)+$'
```

## Troubleshooting

### "Command not found: redoctor"

If you installed with `pip install --user`, ensure your user bin directory is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

### Import Error

If Python can't find the module:

```bash
# Check installation
pip show redoctor

# Reinstall if needed
pip install --force-reinstall redoctor
```

### Permission Denied

On some systems, you may need to use `sudo` or `--user`:

```bash
# Option 1: User install (recommended)
pip install --user redoctor

# Option 2: System install (not recommended)
sudo pip install redoctor
```

## Next Steps

Now that you have ReDoctor installed:

- [Getting Started →](getting-started.md)
- [CLI Reference →](cli.md)
- [Python API →](api.md)
