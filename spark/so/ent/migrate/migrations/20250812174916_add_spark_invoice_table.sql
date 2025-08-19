-- Create "spark_invoices" table
CREATE TABLE "spark_invoices" ("id" uuid NOT NULL, "create_time" timestamptz NOT NULL, "update_time" timestamptz NOT NULL, "spark_invoice" character varying NOT NULL, "expiry_time" timestamptz NULL, PRIMARY KEY ("id"));
-- Create index "spark_invoices_spark_invoice_key" to table: "spark_invoices"
CREATE UNIQUE INDEX "spark_invoices_spark_invoice_key" ON "spark_invoices" ("spark_invoice");
-- Create "token_transaction_spark_invoice" table
CREATE TABLE "token_transaction_spark_invoice" ("token_transaction_id" uuid NOT NULL, "spark_invoice_id" uuid NOT NULL, PRIMARY KEY ("token_transaction_id", "spark_invoice_id"), CONSTRAINT "token_transaction_spark_invoice_spark_invoice_id" FOREIGN KEY ("spark_invoice_id") REFERENCES "spark_invoices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "token_transaction_spark_invoice_token_transaction_id" FOREIGN KEY ("token_transaction_id") REFERENCES "token_transactions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
