-- Drop index "l1token_creates_issuer_public_key_key" from table: "l1token_creates"
DROP INDEX "l1token_creates_issuer_public_key_key";
-- Drop index "l1tokencreate_issuer_public_key" from table: "l1token_creates"
DROP INDEX "l1tokencreate_issuer_public_key";
-- Create index "l1tokencreate_issuer_public_key" to table: "l1token_creates"
CREATE INDEX "l1tokencreate_issuer_public_key" ON "l1token_creates" ("issuer_public_key");
-- Drop index "token_creates_issuer_public_key_key" from table: "token_creates"
DROP INDEX "token_creates_issuer_public_key_key";
-- Drop index "tokencreate_issuer_public_key" from table: "token_creates"
DROP INDEX "tokencreate_issuer_public_key";
-- Create index "tokencreate_issuer_public_key" to table: "token_creates"
CREATE INDEX "tokencreate_issuer_public_key" ON "token_creates" ("issuer_public_key");
