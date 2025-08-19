-- Drop index "tokenoutput_owner_public_key_token_identifier" from table: "token_outputs"
DROP INDEX "tokenoutput_owner_public_key_token_identifier";
-- Drop index "tokenoutput_owner_public_key_token_public_key" from table: "token_outputs"
DROP INDEX "tokenoutput_owner_public_key_token_public_key";
-- Create index "tokenoutput_owner_public_key_token_identifier_status" to table: "token_outputs"
CREATE INDEX "tokenoutput_owner_public_key_token_identifier_status" ON "token_outputs" ("owner_public_key", "token_identifier", "status");
-- Create index "tokenoutput_owner_public_key_token_public_key_status_network" to table: "token_outputs"
CREATE INDEX "tokenoutput_owner_public_key_token_public_key_status_network" ON "token_outputs" ("owner_public_key", "token_public_key", "status", "network");
