#!/usr/bin/env bash
set -e

# Usage: ./scripts/release.sh [patch|minor|major|vX.Y.Z]
# No args = interactive prompt with patch as default.

get_latest_tag() {
    git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"
}

bump_version() {
    local version="$1" part="$2"
    local major minor patch
    version="${version#v}"
    IFS='.' read -r major minor patch <<< "$version"

    case "$part" in
        major) echo "v$((major + 1)).0.0" ;;
        minor) echo "v${major}.$((minor + 1)).0" ;;
        patch) echo "v${major}.${minor}.$((patch + 1))" ;;
    esac
}

validate_semver() {
    if [[ ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: '$1' is not valid semver (expected vX.Y.Z)"
        exit 1
    fi
}

# Ensure we're on main with a clean working tree.
current_branch=$(git branch --show-current)
if [ "$current_branch" != "main" ]; then
    echo "Error: must be on main branch (currently on '$current_branch')"
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "Error: working tree is not clean. Commit or stash changes first."
    exit 1
fi

latest=$(get_latest_tag)

if [ -n "$1" ]; then
    # Non-interactive: argument is patch/minor/major or an explicit version.
    case "$1" in
        patch|minor|major)
            new_version=$(bump_version "$latest" "$1")
            ;;
        v*)
            validate_semver "$1"
            new_version="$1"
            ;;
        *)
            echo "Usage: $0 [patch|minor|major|vX.Y.Z]"
            exit 1
            ;;
    esac
else
    # Interactive.
    default_version=$(bump_version "$latest" "patch")
    echo "Current version: $latest"
    read -p "Enter new version (or press enter for $default_version): " input_version
    new_version="${input_version:-$default_version}"
    validate_semver "$new_version"
fi

# Check tag doesn't already exist.
if git rev-parse "$new_version" >/dev/null 2>&1; then
    echo "Error: tag $new_version already exists"
    exit 1
fi

echo "Tagging $new_version..."
git tag -a "$new_version" -m "Release $new_version"

if [ -n "$1" ]; then
    # Non-interactive: push immediately.
    git push origin "$new_version"
    echo "Pushed $new_version — release workflow triggered."
else
    # Interactive: confirm before pushing.
    read -p "Push tag to origin? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        git push origin "$new_version"
        echo "Pushed $new_version — release workflow triggered."
    else
        echo "Tag created locally. Push with: git push origin $new_version"
    fi
fi
