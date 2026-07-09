#!/bin/bash
# Initialize HiveMind database
# Note: Schema creation is now handled by migrations, not this script

set -e

echo "Initializing HiveMind database..."
echo "Database: ${CLICKHOUSE_DB:-agentstream} (CLICKHOUSE_DB unset -> agentstream for backward compatibility)"
echo ""
echo "Note: Schema will be created/updated by migrations on API startup."
echo "      Run 'make db-migrate' to manually apply migrations."
echo ""
echo "Database initialization complete."
