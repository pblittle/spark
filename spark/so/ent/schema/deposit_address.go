package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/keys"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// DepositAddress is the schema for the deposit addresses table.
type DepositAddress struct {
	ent.Schema
}

// Mixin is the mixin for the deposit addresses table.
func (DepositAddress) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
		NotifyMixin{AdditionalFields: []string{"owner_identity_pubkey", "confirmation_txid"}},
	}
}

// Indexes are the indexes for the deposit addresses table.
func (DepositAddress) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("address"),
		index.Fields("owner_identity_pubkey"),
		index.Fields("owner_signing_pubkey"),
		index.Edges("signing_keyshare"),
		index.Fields("network", "owner_identity_pubkey").Unique().Annotations(entsql.IndexWhere("is_static = true and is_default = true")),
	}
}

// Fields are the fields for the deposit addresses table.
func (DepositAddress) Fields() []ent.Field {
	return []ent.Field{
		field.String("address").
			NotEmpty().
			Immutable().
			Unique().
			Comment("P2TR address string that pays to the combined public key of SOs and the owner's signing public key."),
		field.Enum("network").GoType(st.Network("")).
			Immutable().
			Comment("Network on which the deposit address is valid.").
			Optional(),
		field.Bytes("owner_identity_pubkey").
			Immutable().
			GoType(keys.Public{}).
			Comment("Identity public key of the owner of the deposit address."),
		field.Bytes("owner_signing_pubkey").
			Immutable().
			GoType(keys.Public{}).
			Comment("Signing public key of the owner of the deposit address."),
		field.Int64("confirmation_height").
			Optional().
			Comment("Height of the block that confirmed the deposit address."),
		field.String("confirmation_txid").
			Optional().
			Comment("Transaction ID of the block that confirmed the deposit address."),
		field.JSON("address_signatures", map[string][]byte{}).
			Optional().
			Comment("Address signatures of the deposit address. It is used prove that all SOs have generated the address."),
		field.Bytes("possession_signature").
			Optional().
			Comment("Proof of keyshare possession signature for the deposit address. It is used to prove that the key used by the coordinator to generate the address is known by all SOs."),
		field.UUID("node_id", uuid.UUID{}).
			Optional().
			Comment("Node ID of the deposit address."),
		field.Bool("is_static").
			Default(false).
			Comment("Whether the deposit address is static."),
		field.Bool("is_default").
			Default(true).
			Comment("Whether the deposit address is the default address for the user." +
				"This is only used for static deposit addresses. Static deposit addresses should be unique for the network/user, but since this was not previously enforced, is_default is used to enforce uniqueness."),
	}
}

// Edges are the edges for the deposit addresses table.
func (DepositAddress) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("signing_keyshare", SigningKeyshare.Type).
			Unique().
			Required().
			Immutable(),
		edge.To("utxo", Utxo.Type),
		edge.To("utxoswaps", UtxoSwap.Type),
	}
}
