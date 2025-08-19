-- Modify "token_transactions" table
ALTER TABLE "token_transactions" ADD COLUMN "version" bigint NOT NULL DEFAULT 0;
