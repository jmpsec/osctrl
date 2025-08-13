# Osctrl Release Guide

This document describes how to create releases for Osctrl using GoReleaser.

## Overview

We use [GoReleaser](https://goreleaser.com/) to automate the release process. GoReleaser handles:

- Multi-platform binary builds (Linux, macOS, Windows)
- Docker image creation and publishing
- DEB package creation
- GitHub release creation
- Checksum generation
- Homebrew formula updates

## Prerequisites

### Local Development

1. Install GoReleaser:
   ```bash
   # macOS
   brew install goreleaser/tap/goreleaser

   # Linux
   curl -sfL https://goreleaser.com/static/run | bash -s -- -b /usr/local/bin

   # Windows
   scoop install goreleaser
   ```

2. Install GitHub CLI (optional, for local releases):
   ```bash
   # macOS
   brew install gh

   # Linux
   curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
   sudo apt update && sudo apt install gh
   ```

### GitHub Secrets

Ensure these secrets are configured in your GitHub repository:

- `GITHUB_TOKEN` (automatically provided)
- `DOCKER_HUB_USERNAME` - Your Docker Hub username
- `DOCKER_HUB_ACCESS_TOKEN` - Your Docker Hub access token
- `DOCKER_HUB_ORG` - Your Docker Hub organization

## Release Process

### 1. Local Testing

Before creating a release, test the build process locally:

```bash
# Check if configuration is valid
make release-check

# Build snapshot binaries
make release-build

# Test the built binaries
make release-test
```

### 2. Creating a Release

#### Option A: Automated Release (Recommended)

1. Create and push a tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. The GitHub Actions workflow will automatically:
   - Build all binaries for all platforms
   - Create Docker images
   - Generate DEB packages
   - Create a GitHub release
   - Sign Docker images with cosign

#### Option B: Local Release

1. Create a tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. Create the release locally:
   ```bash
   make release
   ```

### 3. Release Artifacts

Each release includes:

#### Binaries
- `osctrl-tls` - TLS endpoint
- `osctrl-admin` - Admin UI
- `osctrl-api` - API server
- `osctrl-cli` - Command line interface

#### Platforms
- Linux (AMD64, ARM64)
- macOS (AMD64, ARM64)
- Windows (AMD64, ARM64) - CLI only

#### Packages
- DEB packages for Linux
- Docker images for all components
- Source archives

## Configuration

### GoReleaser Configuration

The main configuration is in `.goreleaser.yml`. Key sections:

- **Builds**: Defines how to build each component
- **Archives**: Configures binary packaging
- **Docker**: Sets up Docker image creation
- **NFPM**: Configures DEB package creation
- **Brews**: Sets up Homebrew formula updates

### Customization

To customize the release process:

1. Edit `.goreleaser.yml`
2. Test changes locally:
   ```bash
   make release-check
   make release-build
   ```

3. Commit and push changes

## Troubleshooting

### Common Issues

#### Build Failures

1. Check GoReleaser configuration:
   ```bash
   make release-check
   ```

2. Test individual builds:
   ```bash
   goreleaser build --snapshot --single-target
   ```

#### Docker Build Issues

1. Ensure Docker is running
2. Check Docker Hub credentials
3. Verify Dockerfile paths in `.goreleaser.yml`

#### DEB Package Issues

1. Check NFPM configuration in `.goreleaser.yml`
2. Verify script paths exist
3. Test package creation locally

### Debugging

Enable verbose output:

```bash
goreleaser release --debug
```

### Local Development

For development without creating releases:

```bash
# Build snapshot
goreleaser build --snapshot --clean

# Test specific platform
goreleaser build --snapshot --single-target --id osctrl-cli
```

## Migration from Old Workflow

The old complex GitHub Actions workflow has been replaced with:

- `.github/workflows/release.yml` - Main release workflow
- `.github/workflows/test-release.yml` - Test builds for PRs

### Benefits

1. **Simplified**: Single workflow instead of multiple complex jobs
2. **Standardized**: Uses industry-standard GoReleaser
3. **Reliable**: Fewer moving parts, less prone to errors
4. **Maintainable**: Easier to understand and modify
5. **Feature-rich**: Built-in support for multiple platforms and formats

## Support

For issues with GoReleaser:

- [GoReleaser Documentation](https://goreleaser.com/)
- [GoReleaser GitHub](https://github.com/goreleaser/goreleaser)
- [GoReleaser Discord](https://discord.gg/goreleaser)
