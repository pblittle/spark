package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

type TokenOutput struct {
	ent.Schema
}

func (TokenOutput) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

func (TokenOutput) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("status").GoType(st.TokenOutputStatus("")),
		field.Bytes("owner_public_key").NotEmpty().Immutable(),
		field.Uint64("withdraw_bond_sats").Immutable(),
		field.Uint64("withdraw_relative_block_locktime").Immutable(),
		field.Bytes("withdraw_revocation_commitment").Immutable(),
		field.Bytes("token_public_key").Immutable().Optional(),
		field.Bytes("token_amount").NotEmpty().Immutable(),
		field.Int32("created_transaction_output_vout").Immutable(),
		field.Bytes("spent_ownership_signature").Optional(),
		field.Bytes("spent_operator_specific_ownership_signature").Optional(),
		field.Int32("spent_transaction_input_vout").Optional(),
		field.Bytes("spent_revocation_secret").Optional(),
		field.Bytes("confirmed_withdraw_block_hash").Optional(),
		field.Enum("network").GoType(st.Network("")).Optional(),
		field.Bytes("token_identifier").Immutable(),
		field.UUID("token_create_id", uuid.UUID{}).Immutable(),
	}
}

func (TokenOutput) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("revocation_keyshare", SigningKeyshare.Type).
			Unique().
			Required().
			Immutable(),
		edge.To("output_created_token_transaction", TokenTransaction.Type).
			Unique(),
		// Not required because these are only set once the output has been spent.
		edge.To("output_spent_token_transaction", TokenTransaction.Type).
			Unique(),
		edge.To("token_partial_revocation_secret_shares", TokenPartialRevocationSecretShare.Type).
			Comment("The partial revocation secret shares gathered from each SO for this token output."),
		// Add immutable and required after backfill.
		edge.
			From("token_create", TokenCreate.Type).
			Ref("token_output").
			Immutable().
			Unique().
			Required().
			Field("token_create_id").
			Comment("Token create contains the token metadata associated with this output."),
	}
}

func (TokenOutput) Indexes() []ent.Index {
	return []ent.Index{
		// Optimized for GetOwnedTokenOutputs query: high cardinality fields first, then low cardinality enums.
		// Supports: owner_public_key, owner_public_key+token_public_key, owner_public_key+token_public_key+status, etc.
		index.Fields("owner_public_key", "token_public_key", "status", "network"),
		// Omit network because token identifier is unique per network.
		index.Fields("owner_public_key", "token_identifier", "status"),
		// Enables quick unmarking of withdrawn outputs in response to block reorgs.
		index.Fields("confirmed_withdraw_block_hash"),
		// Optimize pre-emption queries by indexing the spent transaction relationship
		index.Edges("output_spent_token_transaction"),
		index.Edges("output_created_token_transaction").Fields("created_transaction_output_vout").Unique(),
		index.Fields("token_create_id"),
	}
}
