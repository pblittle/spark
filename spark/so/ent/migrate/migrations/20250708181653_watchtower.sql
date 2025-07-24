-- Modify "transfer_leafs" table
ALTER TABLE "transfer_leafs" ADD COLUMN "previous_direct_refund_tx" bytea NULL, ADD COLUMN "previous_direct_from_cpfp_refund_tx" bytea NULL, ADD COLUMN "intermediate_direct_refund_tx" bytea NULL, ADD COLUMN "intermediate_direct_from_cpfp_refund_tx" bytea NULL;
-- Modify "tree_nodes" table
ALTER TABLE "tree_nodes" ADD COLUMN "direct_tx" bytea NULL, ADD COLUMN "direct_from_cpfp_refund_tx" bytea NULL;
