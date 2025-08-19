-- Modify "spark_invoices" table
ALTER TABLE "spark_invoices" ADD COLUMN "receiver_public_key" bytea NOT NULL;
