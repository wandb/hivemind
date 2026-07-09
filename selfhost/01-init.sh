#!/bin/bash
# Initialize AgentStream database
# Note: Schema creation is now handled by migrations, not this script

set -e

echo "Initializing AgentStream database..."
echo "Database: ${CLICKHOUSE_DB:-agentstream}"
echo ""
echo "Note: Schema will be created/updated by migrations on API startup."
echo "      Run 'make db-migrate' to manually apply migrations."
echo ""
echo "Database initialization complete."
