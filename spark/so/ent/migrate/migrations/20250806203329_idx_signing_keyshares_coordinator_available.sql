-- Create index "idx_signing_keyshares_coordinator_available" to table: "signing_keyshares"
CREATE INDEX "idx_signing_keyshares_coordinator_available" ON "signing_keyshares" ("coordinator_index") WHERE ((status)::text = 'AVAILABLE'::text);
