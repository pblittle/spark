package secretsharing

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common/secret_sharing/curve"
	"github.com/lightsparkdev/spark/common/secret_sharing/polynomial"
)

// Helper function to create test shares for a secret
func createTestShares(secret *secp256k1.ModNScalar, threshold, numShares int) ([]*secp256k1.ModNScalar, error) {
	// Create polynomial with secret as constant term
	poly, err := polynomial.NewScalarPolynomialSharing(secret, threshold-1)
	if err != nil {
		return nil, err
	}

	shares := make([]*secp256k1.ModNScalar, numShares)
	for i := range numShares {
		x := curve.ScalarFromInt(uint32(i + 1)) // Party IDs start from 1
		shares[i] = poly.Eval(x)
	}

	return shares, nil
}

// Test basic redistribution protocol flow
func TestBasicRedistribution(t *testing.T) {
	// Test configuration: (2,3) -> (3,4)
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 3,
		OldParties:   []ShareID{1, 2, 3},
		NewParties:   []ShareID{4, 5, 6, 7},
	}

	// Create a test secret
	secret := curve.ScalarFromInt(12345)

	// Create initial shares for old parties
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	// Create the threshold number of shareholders.
	oldShareholdersQuorum := make([]*OldShareHolder, config.OldThreshold)
	for i, shareID := range config.OldParties[:config.OldThreshold] {
		oldShareholdersQuorum[i] = NewOldShareHolder(shareID, oldShares[i], config)
	}

	// Create new shareholders
	newShareholders := make([]*NewShareHolder, len(config.NewParties))
	for i, shareID := range config.NewParties {
		newShareholders[i] = NewNewShareHolder(shareID, config)
	}

	// Create secret commitment g^k
	secretCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, secretCommitment)

	// Round 1: Old shareholders send subshares to new shareholders
	allDirectMessages := make([]DirectMessage[Round1DirectPayload], 0)
	allBroadcasts := make([]BroadcastMessage[Round1BroadcastPayload], 0)

	for _, oldSH := range oldShareholdersQuorum {
		directs, broadcasts, err := oldSH.SendSubshares(secretCommitment)
		if err != nil {
			t.Fatalf("Failed to send subshares for party %d: %v", oldSH.ID, err)
		}

		allDirectMessages = append(allDirectMessages, directs...)
		allBroadcasts = append(allBroadcasts, broadcasts...)
	}

	// Verify we have the expected number of messages
	expectedDirectMessages := len(oldShareholdersQuorum) * len(newShareholders)
	if len(allDirectMessages) != expectedDirectMessages {
		t.Errorf("Expected %d direct messages, got %d", expectedDirectMessages, len(allDirectMessages))
	}

	expectedBroadcasts := len(oldShareholdersQuorum)
	if len(allBroadcasts) != expectedBroadcasts {
		t.Errorf("Expected %d broadcasts, got %d", expectedBroadcasts, len(allBroadcasts))
	}

	// Round 2: New shareholders verify subshares and decide
	round1States := make(map[ShareID]*Round1State)
	allRound2Broadcasts := make([]BroadcastMessage[Round2Payload], 0)

	for _, newSH := range newShareholders {
		state, decisions, err := newSH.VerifyAndDecide(allDirectMessages, allBroadcasts)
		if err != nil {
			t.Fatalf("VerifyAndDecide failed for new party %d: %v", newSH.ID, err)
		}

		// Verify the party decided to commit
		if len(decisions) != 1 || decisions[0].Payload.Decision != "commit" {
			t.Errorf("Expected party %d to commit, got decision: %v", newSH.ID, decisions)
		}

		round1States[newSH.ID] = state
		allRound2Broadcasts = append(allRound2Broadcasts, decisions...)
	}

	// Verify we have decisions from all new parties
	if len(allRound2Broadcasts) != len(newShareholders) {
		t.Errorf("Expected %d Round2 broadcasts, got %d", len(newShareholders), len(allRound2Broadcasts))
	}

	// Round 3: New shareholders generate their new shares
	newShares := make([]*secp256k1.ModNScalar, len(newShareholders))
	for i, newSH := range newShareholders {
		state := round1States[newSH.ID]
		newShare, err := newSH.GenerateNewShare(state, allRound2Broadcasts)
		if err != nil {
			t.Fatalf("GenerateNewShare failed for new party %d: %v", newSH.ID, err)
		}

		newShares[i] = newShare
	}

	// Verify that the new shares can reconstruct the original secret
	// Use any subset of size config.NewThreshold to test reconstruction
	testPairs := make([]*polynomial.ScalarEval, config.NewThreshold)
	for i := range config.NewThreshold {
		shareID := config.NewParties[i]
		x := curve.ScalarFromInt(uint32(shareID))
		testPairs[i] = &polynomial.ScalarEval{X: x, Y: newShares[i]}
	}

	// Reconstruct the secret using the new shares
	reconstructedSecret := polynomial.ReconstructScalar(testPairs)

	// Verify it matches the original secret
	if !reconstructedSecret.Equals(secret) {
		t.Errorf("Secret reconstruction failed!")
		t.Errorf("Original secret: %s", secret.String())
		t.Errorf("Reconstructed:  %s", reconstructedSecret.String())
	} else {
		t.Logf("Successfully reconstructed original secret!")
	}

	t.Logf("Successfully completed redistribution protocol")
	t.Logf("Generated %d new shares", len(newShares))
}

// Test that verification catches invalid subshares
func TestInvalidSubshareDetection(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []ShareID{1, 2},
		NewParties:   []ShareID{3, 4},
	}

	secret := curve.ScalarFromInt(54321)
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	// Create one honest and one malicious old shareholder
	honestSH := NewOldShareHolder(1, oldShares[0], config)
	maliciousSH := NewOldShareHolder(2, oldShares[1], config)

	newSH := NewNewShareHolder(3, config)

	secretCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, secretCommitment)

	// Get honest messages
	honestDirects, honestBroadcasts, err := honestSH.SendSubshares(secretCommitment)
	if err != nil {
		t.Fatalf("Honest party failed to send subshares: %v", err)
	}

	// Get malicious messages and corrupt a subshare
	maliciousDirects, maliciousBroadcasts, err := maliciousSH.SendSubshares(secretCommitment)
	if err != nil {
		t.Fatalf("Malicious party failed to send subshares: %v", err)
	}

	// Corrupt one of the malicious subshares
	for i := range maliciousDirects {
		if maliciousDirects[i].ToID == newSH.ID {
			// Replace with random garbage
			maliciousDirects[i].Payload.Subshare = curve.EncodeScalar(curve.ScalarFromInt(99999))
			break
		}
	}

	// Combine all messages
	allDirects := append(honestDirects, maliciousDirects...)
	allBroadcasts := append(honestBroadcasts, maliciousBroadcasts...)

	// New shareholder should detect the corruption
	_, decisions, err := newSH.VerifyAndDecide(allDirects, allBroadcasts)

	// Should either return an error or broadcast "abort"
	if err == nil && len(decisions) > 0 && decisions[0].Payload.Decision == "commit" {
		t.Error("Expected new shareholder to detect corruption and abort, but it committed")
	}

	if len(decisions) > 0 && decisions[0].Payload.Decision == "abort" {
		t.Log("Successfully detected corrupted subshare")
	} else if err != nil {
		t.Logf("Successfully detected corruption with error: %v", err)
	}
}

// Test that mismatched secret commitments are detected
func TestSecretCommitmentMismatch(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []ShareID{1, 2},
		NewParties:   []ShareID{3},
	}

	secret := curve.ScalarFromInt(11111)
	oldShares, err := createTestShares(secret, config.OldThreshold, len(config.OldParties))
	if err != nil {
		t.Fatalf("Failed to create test shares: %v", err)
	}

	oldSH1 := NewOldShareHolder(1, oldShares[0], config)
	oldSH2 := NewOldShareHolder(2, oldShares[1], config)
	newSH := NewNewShareHolder(3, config)

	// Create two different secret commitments
	correctCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(secret, correctCommitment)

	wrongSecret := curve.ScalarFromInt(22222)
	wrongCommitment := new(secp256k1.JacobianPoint)
	secp256k1.ScalarBaseMultNonConst(wrongSecret, wrongCommitment)

	// Old shareholder 1 uses correct commitment
	directs1, broadcasts1, err := oldSH1.SendSubshares(correctCommitment)
	if err != nil {
		t.Fatalf("OldSH1 SendSubshares failed: %v", err)
	}

	// Old shareholder 2 uses wrong commitment
	directs2, broadcasts2, err := oldSH2.SendSubshares(wrongCommitment)
	if err != nil {
		t.Fatalf("OldSH2 SendSubshares failed: %v", err)
	}

	// Combine messages
	allDirects := append(directs1, directs2...)
	allBroadcasts := append(broadcasts1, broadcasts2...)

	// New shareholder should detect the mismatch
	_, decisions, err := newSH.VerifyAndDecide(allDirects, allBroadcasts)

	if err == nil && len(decisions) > 0 && decisions[0].Payload.Decision == "commit" {
		t.Error("Expected detection of secret commitment mismatch, but party committed")
	}

	if len(decisions) > 0 && decisions[0].Payload.Decision == "abort" {
		t.Log("Successfully detected secret commitment mismatch")
	} else if err != nil {
		t.Logf("Successfully detected mismatch with error: %v", err)
	}
}

// Test abort propagation in Round 3
func TestAbortPropagation(t *testing.T) {
	config := &RedistConfig{
		OldThreshold: 2,
		NewThreshold: 2,
		OldParties:   []ShareID{1, 2},
		NewParties:   []ShareID{3, 4},
	}

	newSH1 := NewNewShareHolder(3, config)
	newSH2 := NewNewShareHolder(4, config)

	// Create fake Round1 state (doesn't matter for this test)
	fakeState := &Round1State{
		ReceivedSubshares:   make(map[ShareID]curve.ScalarBytes),
		ReceivedCommitments: make(map[ShareID]*Round1BroadcastPayload),
	}

	// Create decision broadcasts where one party aborts
	decisions := []BroadcastMessage[Round2Payload]{
		{FromID: 3, Payload: Round2Payload{Decision: "commit"}},
		{FromID: 4, Payload: Round2Payload{Decision: "abort"}},
	}

	// Both parties should fail in GenerateNewShare due to the abort
	_, err1 := newSH1.GenerateNewShare(fakeState, decisions)
	_, err2 := newSH2.GenerateNewShare(fakeState, decisions)

	if err1 == nil {
		t.Error("Expected party 3 to fail GenerateNewShare due to abort, but it succeeded")
	}

	if err2 == nil {
		t.Error("Expected party 4 to fail GenerateNewShare due to abort, but it succeeded")
	}

	t.Logf("Successfully detected abort propagation: %v, %v", err1, err2)
}
