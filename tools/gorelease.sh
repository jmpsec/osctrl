#!/usr/bin/env bash
#
# Helper script to use GoReleaser for building and releasing osctrl
#
# Usage: ./gorelease.sh [-h|--help|help] [COMMAND]

# Stop script on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if goreleaser is installed
if ! command -v goreleaser &> /dev/null; then
    print_error "GoReleaser is not installed. Please install it first:"
    echo "  brew install goreleaser/tap/goreleaser"
    echo "  or visit: https://goreleaser.com/install/"
    exit 1
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository"
    exit 1
fi

# Check if we have uncommitted changes
if ! git diff-index --quiet HEAD --; then
    print_warning "You have uncommitted changes. Please commit or stash them first."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build     Build binaries locally (snapshot)"
    echo "  release   Create a new release (requires tag)"
    echo "  check     Check if the configuration is valid"
    echo "  init      Initialize a new release"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build                    # Build snapshot binaries"
    echo "  $0 check                    # Validate configuration"
    echo "  $0 init                     # Initialize release process"
    echo "  git tag v1.0.0 && $0 release # Create release for v1.0.0"
}

# Function to build snapshot
build_snapshot() {
    print_status "Building snapshot binaries..."
    goreleaser build --snapshot --clean
    print_status "Build completed! Check the dist/ directory."
}

# Function to check configuration
check_config() {
    print_status "Checking GoReleaser configuration..."
    goreleaser check
    print_status "Configuration is valid!"
}

# Function to initialize release
init_release() {
    print_status "Initializing release process..."
    goreleaser init
    print_status "Release configuration initialized!"
    print_warning "Please review and customize the generated .goreleaser.yml file."
}

# Function to create release
create_release() {
    # Check if we're on a tag
    if ! git describe --exact-match --tags HEAD > /dev/null 2>&1; then
        print_error "Not on a tag. Please create a tag first:"
        echo "  git tag v1.0.0"
        echo "  git push origin v1.0.0"
        exit 1
    fi

    TAG=$(git describe --exact-match --tags HEAD)
    print_status "Creating release for tag: $TAG"

    # Check if release already exists
    if gh release view "$TAG" > /dev/null 2>&1; then
        print_warning "Release for tag $TAG already exists!"
        read -p "Continue and overwrite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Create release
    goreleaser release --clean
    print_status "Release created successfully!"
}

# Main script logic
case "${1:-help}" in
    build)
        build_snapshot
        ;;
    release)
        create_release
        ;;
    check)
        check_config
        ;;
    init)
        init_release
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
