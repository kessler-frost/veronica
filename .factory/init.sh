#!/bin/bash
set -e

cd /Users/fimbulwinter/dev/veronica

# Agentfield SDK uses subdirectory module but lacks proper tags.
# These env vars allow go mod tidy to resolve the pseudo-version via replace directive.
export GONOSUMCHECK='github.com/Agent-Field/*'
export GONOSUMDB='github.com/Agent-Field/*'
export GOPRIVATE='github.com/Agent-Field/*'

# Fix go.sum if needed
go mod tidy 2>/dev/null || true

# Sync Python dependencies
uv sync 2>/dev/null || true

echo "init.sh complete"
