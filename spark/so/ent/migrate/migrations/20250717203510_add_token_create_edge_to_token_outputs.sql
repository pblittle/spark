-- Modify "token_outputs" table
ALTER TABLE "token_outputs" ADD COLUMN "token_create_id" uuid NULL, ADD CONSTRAINT "token_outputs_token_creates_token_output" FOREIGN KEY ("token_create_id") REFERENCES "token_creates" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;
-- Create index "tokenoutput_token_create_id" to table: "token_outputs"
CREATE INDEX "tokenoutput_token_create_id" ON "token_outputs" ("token_create_id");
