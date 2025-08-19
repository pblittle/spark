-- Modify "token_freezes" table
ALTER TABLE "token_freezes" ALTER COLUMN "token_public_key" DROP NOT NULL, ADD COLUMN "token_create_id" uuid NULL, ADD CONSTRAINT "token_freezes_token_creates_token_freeze" FOREIGN KEY ("token_create_id") REFERENCES "token_creates" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;
-- Create index "tokenfreeze_owner_public_key_token_create_id_wallet_provided_f" to table: "token_freezes"
CREATE UNIQUE INDEX "tokenfreeze_owner_public_key_token_create_id_wallet_provided_f" ON "token_freezes" ("owner_public_key", "token_create_id", "wallet_provided_freeze_timestamp");
-- Create index "tokenfreeze_owner_public_key_token_create_id_wallet_provided_t" to table: "token_freezes"
CREATE UNIQUE INDEX "tokenfreeze_owner_public_key_token_create_id_wallet_provided_t" ON "token_freezes" ("owner_public_key", "token_create_id", "wallet_provided_thaw_timestamp");
