-- Create "signing_commitments" table
CREATE TABLE "signing_commitments" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "operator_index" bigint NOT NULL, "status" character varying NOT NULL, "nonce_commitment" bytea NOT NULL, PRIMARY KEY ("id"));
-- Create index "signing_commitments_nonce_commitment_key" to table: "signing_commitments"
CREATE UNIQUE INDEX "signing_commitments_nonce_commitment_key" ON "signing_commitments" ("nonce_commitment");
-- Create index "signingcommitment_operator_index_status" to table: "signing_commitments"
CREATE INDEX "signingcommitment_operator_index_status" ON "signing_commitments" ("operator_index", "status");
