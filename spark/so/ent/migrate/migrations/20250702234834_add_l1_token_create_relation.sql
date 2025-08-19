-- Modify "token_creates" table
ALTER TABLE "token_creates" ADD COLUMN "token_create_l1_token_create" uuid NULL, ADD CONSTRAINT "token_creates_l1token_creates_l1_token_create" FOREIGN KEY ("token_create_l1_token_create") REFERENCES "l1token_creates" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;
