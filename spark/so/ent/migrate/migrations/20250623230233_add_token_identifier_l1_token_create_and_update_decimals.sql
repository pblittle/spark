-- Modify "token_creates" table
ALTER TABLE "token_creates" ALTER COLUMN "decimals" TYPE smallint, ADD COLUMN "token_identifier" bytea NOT NULL;
-- Create index "token_creates_token_identifier_key" to table: "token_creates"
CREATE UNIQUE INDEX "token_creates_token_identifier_key" ON "token_creates" ("token_identifier");
-- Create index "tokencreate_token_identifier" to table: "token_creates"
CREATE UNIQUE INDEX "tokencreate_token_identifier" ON "token_creates" ("token_identifier");
-- Create "l1token_creates" table
CREATE TABLE "l1token_creates" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "issuer_public_key" bytea NOT NULL, "token_name" character varying NOT NULL, "token_ticker" character varying NOT NULL, "decimals" smallint NOT NULL, "max_supply" bytea NOT NULL, "is_freezable" boolean NOT NULL, "network" character varying NOT NULL, "token_identifier" bytea NOT NULL, "transaction_id" bytea NOT NULL, PRIMARY KEY ("id"));
-- Create index "l1token_creates_issuer_public_key_key" to table: "l1token_creates"
CREATE UNIQUE INDEX "l1token_creates_issuer_public_key_key" ON "l1token_creates" ("issuer_public_key");
-- Create index "l1token_creates_token_identifier_key" to table: "l1token_creates"
CREATE UNIQUE INDEX "l1token_creates_token_identifier_key" ON "l1token_creates" ("token_identifier");
-- Create index "l1token_creates_transaction_id_key" to table: "l1token_creates"
CREATE UNIQUE INDEX "l1token_creates_transaction_id_key" ON "l1token_creates" ("transaction_id");
-- Create index "l1tokencreate_issuer_public_key" to table: "l1token_creates"
CREATE UNIQUE INDEX "l1tokencreate_issuer_public_key" ON "l1token_creates" ("issuer_public_key");
-- Create index "l1tokencreate_token_identifier" to table: "l1token_creates"
CREATE UNIQUE INDEX "l1tokencreate_token_identifier" ON "l1token_creates" ("token_identifier");
