package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// TreeNode is the schema for the tree nodes table.
type TreeNode struct {
	ent.Schema
}

// Mixin is the mixin for the tree nodes table.
func (TreeNode) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields are the fields for the tree nodes table.
func (TreeNode) Fields() []ent.Field {
	return []ent.Field{
		field.Uint64("value").Immutable(),
		field.Enum("status").GoType(st.TreeNodeStatus("")),
		field.Bytes("verifying_pubkey").NotEmpty().Immutable(),
		field.Bytes("owner_identity_pubkey").NotEmpty(),
		field.Bytes("owner_signing_pubkey").NotEmpty(),

		field.Int16("vout"),

		field.Uint64("node_confirmation_height").Optional(),
		field.Uint64("refund_confirmation_height").Optional(),

		// Node transactions
		field.Bytes("raw_tx").NotEmpty(),
		field.Bytes("direct_tx").Optional(),
		field.Bytes("direct_from_cpfp_refund_tx").Optional(),
		field.Bytes("raw_txid").Optional().Comment("Valid transaction ID of the stored node transaction"),
		field.Bytes("direct_txid").Optional().Comment("Valid transaction ID of the stored direct node transaction"),
		field.Bytes("direct_from_cpfp_refund_txid").Optional().Comment("Valid transaction ID of the stored direct from CPFP node transaction"),

		// Refund transactions
		field.Bytes("raw_refund_tx").Optional().Comment("A transaction to exit Spark unilaterally. Only leafs have this transaction."),
		field.Bytes("direct_refund_tx").Optional(),
		field.Bytes("raw_refund_txid").Optional().Comment("Valid transaction ID of the stored refund transaction"),
		field.Bytes("direct_refund_txid").Optional().Comment("Valid transaction ID of the direct refund transaction"),
	}
}

// Edges are the edges for the tree nodes table.
func (TreeNode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("tree", Tree.Type).
			Unique().
			Required(),
		edge.To("parent", TreeNode.Type).
			Unique(),
		edge.To("signing_keyshare", SigningKeyshare.Type).
			Unique().
			Required(),
		edge.From("children", TreeNode.Type).Ref("parent"),
	}
}

// Indexes are the indexes for the tree nodes table.
func (TreeNode) Indexes() []ent.Index {
	return []ent.Index{
		index.Edges("parent"),
		index.Edges("tree"),
		index.Edges("signing_keyshare"),
		index.Fields("owner_identity_pubkey"),
		index.Fields("owner_identity_pubkey", "status"),
		index.Fields("node_confirmation_height"),
		index.Fields("refund_confirmation_height"),
		index.Fields("update_time"),

		index.Fields("raw_txid").Annotations(
			entsql.IndexWhere("raw_txid is not null"),
		),
		index.Fields("direct_txid").Annotations(
			entsql.IndexWhere("direct_txid is not null"),
		),
		index.Fields("direct_from_cpfp_refund_txid").Annotations(
			entsql.IndexWhere("direct_from_cpfp_refund_txid is not null"),
		),

		index.Fields("raw_refund_txid").Annotations(
			entsql.IndexWhere("raw_refund_txid is not null"),
		),
		index.Fields("direct_refund_txid").Annotations(
			entsql.IndexWhere("direct_refund_txid is not null"),
		),
	}
}
