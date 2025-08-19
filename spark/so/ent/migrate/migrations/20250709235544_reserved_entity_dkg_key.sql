-- Create "entity_dkg_keys" table
CREATE TABLE "entity_dkg_keys" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "key_type" character varying NOT NULL DEFAULT 'initial_entity_dkg_key', "entity_dkg_key_signing_keyshare" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "entity_dkg_keys_signing_keyshares_signing_keyshare" FOREIGN KEY ("entity_dkg_key_signing_keyshare") REFERENCES "signing_keyshares" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "entitydkgkey_key_type" to table: "entity_dkg_keys"
CREATE UNIQUE INDEX "entitydkgkey_key_type" ON "entity_dkg_keys" ("key_type");
