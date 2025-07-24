-- Create index "tokenmint_issuer_public_key" to table: "token_mints"
CREATE INDEX "tokenmint_issuer_public_key" ON "token_mints" ("issuer_public_key");
-- Create index "tokenmint_token_identifier" to table: "token_mints"
CREATE INDEX "tokenmint_token_identifier" ON "token_mints" ("token_identifier");
