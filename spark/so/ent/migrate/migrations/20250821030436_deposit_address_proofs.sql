-- Modify "deposit_addresses" table
ALTER TABLE "deposit_addresses" ADD COLUMN "address_signatures" jsonb NULL, ADD COLUMN "possession_signature" bytea NULL;
