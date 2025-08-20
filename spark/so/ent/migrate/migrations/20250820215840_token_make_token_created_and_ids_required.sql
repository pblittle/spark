-- Modify "token_outputs" table
ALTER TABLE "token_outputs" DROP CONSTRAINT "token_outputs_token_creates_token_output", ALTER COLUMN "token_identifier" SET NOT NULL, ALTER COLUMN "token_create_id" SET NOT NULL, ADD CONSTRAINT "token_outputs_token_creates_token_output" FOREIGN KEY ("token_create_id") REFERENCES "token_creates" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION;
