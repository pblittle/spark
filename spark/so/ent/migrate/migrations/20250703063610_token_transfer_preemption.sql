-- Create index "tokenoutput_token_output_output_spent_token_transaction" to table: "token_outputs"
CREATE INDEX "tokenoutput_token_output_output_spent_token_transaction" ON "token_outputs" ("token_output_output_spent_token_transaction");
-- Modify "token_transactions" table
ALTER TABLE "token_transactions" ADD COLUMN "client_created_timestamp" timestamptz NULL;
