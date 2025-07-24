-- Create index "tokenoutput_created_transactio_fffad638156bf64b1c3f80bffd25831f" to table: "token_outputs"
CREATE UNIQUE INDEX "tokenoutput_created_transactio_fffad638156bf64b1c3f80bffd25831f" ON "token_outputs" ("created_transaction_output_vout", "token_output_output_created_token_transaction");
