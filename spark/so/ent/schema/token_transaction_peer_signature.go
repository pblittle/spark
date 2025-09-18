package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/lightsparkdev/spark/common/keys"
)

type TokenTransactionPeerSignature struct {
	ent.Schema
}

func (TokenTransactionPeerSignature) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

func (TokenTransactionPeerSignature) Annotations() []schema.Annotation {
	return []schema.Annotation{
		schema.Comment("Holds the signatures for a token transaction from the peer operators. " +
			"DO NOT WRITE an operator's own signature in this table. That already exists in the TokenTransaction table."),
	}
}

func (TokenTransactionPeerSignature) Fields() []ent.Field {
	return []ent.Field{
		field.Bytes("operator_identity_public_key").GoType(keys.Public{}),
		field.Bytes("signature").NotEmpty(),
	}
}

func (TokenTransactionPeerSignature) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("token_transaction", TokenTransaction.Type).
			Ref("peer_signatures").
			Unique().
			Required(),
	}
}

func (TokenTransactionPeerSignature) Indexes() []ent.Index {
	return []ent.Index{
		index.Edges("token_transaction"),
		index.Fields("operator_identity_public_key").
			Edges("token_transaction").
			Unique().
			Annotations(
				schema.Comment(
					"Ensures each operator can add at most one peer signature for a given token transaction.",
				),
			),
	}
}
