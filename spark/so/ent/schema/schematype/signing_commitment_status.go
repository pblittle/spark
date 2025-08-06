package schematype

type SigningCommitmentStatus string

const (
	SigningCommitmentStatusAvailable SigningCommitmentStatus = "AVAILABLE"
	SigningCommitmentStatusUsed      SigningCommitmentStatus = "USED"
)

func (SigningCommitmentStatus) Values() []string {
	return []string{
		string(SigningCommitmentStatusAvailable),
		string(SigningCommitmentStatusUsed),
	}
}
