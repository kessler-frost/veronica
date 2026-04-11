#!/bin/bash
set -e

cd /Users/fimbulwinter/dev/veronica

# Fix go.sum if needed
go mod tidy 2>/dev/null || true

# Sync Python dependencies
uv sync 2>/dev/null || true

echo "init.sh complete"
