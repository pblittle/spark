package helper

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/handler/signing_handler"
	"github.com/lightsparkdev/spark/so/objects"
	"google.golang.org/grpc"

	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
)

var (
	ErrNegativeOutputValue                        = errors.New("output value is negative, which is not allowed")
	ErrTotalOutputValueGreaterThanMaxInt64        = errors.New("total output value is greater than MaxInt64, which is not allowed")
	ErrTotalOutputValueGreaterThanPrevOutputValue = errors.New("total output value is greater than the previous output value")
)

// SigningResult is the result of a signing job.
type SigningResult struct {
	// JobID is the ID of the signing job.
	JobID string
	// Message is the message that was signed.
	Message []byte
	// SignatureShares is the signature shares from all operators.
	SignatureShares map[string][]byte
	// SigningCommitments is the signing commitments from all operators.
	SigningCommitments map[string]objects.SigningCommitment
	// PublicKeys is the public keys from all operators.
	PublicKeys map[string][]byte
	// KeyshareOwnerIdentifiers is the identifiers of the keyshare owners.
	KeyshareOwnerIdentifiers []string
	// KeyshareThreshold is the threshold of the keyshare.
	KeyshareThreshold uint32
}

// MarshalProto marshals the signing result to a proto.
func (s *SigningResult) MarshalProto() (*pbspark.SigningResult, error) {
	signingCommitments, err := common.ConvertObjectMapToProtoMap(s.SigningCommitments)
	if err != nil {
		return nil, err
	}

	signingKeyshare := &pbspark.SigningKeyshare{
		OwnerIdentifiers: s.KeyshareOwnerIdentifiers,
		Threshold:        s.KeyshareThreshold,
	}
	return &pbspark.SigningResult{
		SigningNonceCommitments: signingCommitments,
		SignatureShares:         s.SignatureShares,
		PublicKeys:              s.PublicKeys,
		SigningKeyshare:         signingKeyshare,
	}, nil
}

type SparkServiceConnection interface {
	Connection() *grpc.ClientConn
	Close()
	NewClient() pbinternal.SparkInternalServiceClient
}

type SparkServiceClientFactory interface {
	NewConnection(operator *so.SigningOperator) (SparkServiceConnection, error)
	IsMock() bool
}

type SparkServiceConnectionImpl struct {
	conn *grpc.ClientConn
}

type SparkServiceClientFactoryImpl struct{}

func (c *SparkServiceClientFactoryImpl) NewConnection(operator *so.SigningOperator) (SparkServiceConnection, error) {
	conn, err := operator.NewGRPCConnection()
	if err != nil {
		return nil, err
	}
	return &SparkServiceConnectionImpl{conn: conn}, nil
}

func (c *SparkServiceClientFactoryImpl) IsMock() bool {
	return false
}

func (c *SparkServiceConnectionImpl) Connection() *grpc.ClientConn {
	return c.conn
}

func (c *SparkServiceConnectionImpl) Close() {
	// Note that conn.Close() actually does return an error, but in all our use
	// cases, we ignore it anyway, so we don't bother to return it here.
	c.conn.Close()
}

func (c *SparkServiceConnectionImpl) NewClient() pbinternal.SparkInternalServiceClient {
	return pbinternal.NewSparkInternalServiceClient(c.conn)
}

// frostRound1 performs the first round of the Frost signing. It gathers the signing commitments from all operators.
func frostRound1(ctx context.Context, config *so.Config, signingKeyshareIDs []uuid.UUID, operatorSelection *OperatorSelection, publicKeyMap map[string][]byte, count uint32, sparkServiceClientFactory SparkServiceClientFactory) (map[string][]objects.SigningCommitment, error) {
	return ExecuteTaskWithAllOperators(ctx, config, operatorSelection, func(ctx context.Context, operator *so.SigningOperator) ([]objects.SigningCommitment, error) {
		keyshareIDs := make([]string, len(signingKeyshareIDs))
		for i, id := range signingKeyshareIDs {
			keyshareIDs[i] = id.String()
		}

		request := &pbinternal.FrostRound1Request{
			KeyshareIds: keyshareIDs,
			PublicKeys:  publicKeyMap,
			Count:       count,
		}

		var response *pbinternal.FrostRound1Response
		if operator.Identifier == config.Identifier && !sparkServiceClientFactory.IsMock() {
			var err error
			handler := signing_handler.NewFrostSigningHandler(config)
			response, err = handler.FrostRound1(ctx, request)
			if err != nil {
				return nil, err
			}
		} else {
			conn, err := sparkServiceClientFactory.NewConnection(operator)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			client := conn.NewClient()
			response, err = client.FrostRound1(ctx, request)
			if err != nil {
				return nil, err
			}
		}

		commitments := make([]objects.SigningCommitment, len(response.SigningCommitments))
		for i, commitment := range response.SigningCommitments {
			err := commitments[i].UnmarshalProto(commitment)
			if err != nil {
				return nil, err
			}
		}

		return commitments, nil
	})
}

// frostRound2 performs the second round of the Frost signing. It gathers the signature shares from all operators.
func frostRound2(
	ctx context.Context,
	config *so.Config,
	jobs []*SigningJob,
	round1 map[string][]objects.SigningCommitment,
	operatorSelection *OperatorSelection,
	sparkServiceClientFactory SparkServiceClientFactory,
) (map[string]map[string][]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)
	for _, job := range jobs {
		logger.Info("FrostRound2 signing job message", "message", hex.EncodeToString(job.Message))
		logger.Info("FrostRound2 signing job verifying key", "verifyingKey", hex.EncodeToString(job.VerifyingKey))
	}
	operatorResult, err := ExecuteTaskWithAllOperators(ctx, config, operatorSelection, func(ctx context.Context, operator *so.SigningOperator) (map[string][]byte, error) {
		commitmentsArray := common.MapOfArrayToArrayOfMap(round1)

		signingJobs := make([]*pbinternal.SigningJob, len(jobs))
		for i, job := range jobs {
			commitments := make(map[string]*pbcommon.SigningCommitment)
			for operatorID, commitment := range commitmentsArray[i] {
				commitmentProto, err := commitment.MarshalProto()
				if err != nil {
					return nil, err
				}
				commitments[operatorID] = commitmentProto
			}
			var userCommitmentProto *pbcommon.SigningCommitment
			if job.UserCommitment != nil {
				var err error
				userCommitmentProto, err = job.UserCommitment.MarshalProto()
				if err != nil {
					return nil, err
				}
			}
			signingJobs[i] = &pbinternal.SigningJob{
				JobId:            job.JobID,
				Message:          job.Message,
				KeyshareId:       job.SigningKeyshareID.String(),
				VerifyingKey:     job.VerifyingKey,
				Commitments:      commitments,
				UserCommitments:  userCommitmentProto,
				AdaptorPublicKey: job.AdaptorPublicKey,
			}
		}

		request := &pbinternal.FrostRound2Request{
			SigningJobs: signingJobs,
		}

		var response *pbinternal.FrostRound2Response
		if operator.Identifier == config.Identifier && !sparkServiceClientFactory.IsMock() {
			handler := signing_handler.NewFrostSigningHandler(config)
			var err error
			response, err = handler.FrostRound2(ctx, request)
			if err != nil {
				return nil, err
			}
		} else {
			conn, err := sparkServiceClientFactory.NewConnection(operator)
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			client := conn.NewClient()
			response, err = client.FrostRound2(ctx, request)
			if err != nil {
				return nil, err
			}
		}

		results := make(map[string][]byte)
		for operatorID, result := range response.Results {
			results[operatorID] = result.SignatureShare
		}

		return results, nil
	})
	if err != nil {
		return nil, err
	}

	result := common.SwapMapKeys(operatorResult)
	return result, nil
}

// SigningJob is a job for signing.
type SigningJob struct {
	// JobID is the ID of the signing job.
	JobID string
	// SigningKeyshareID is the ID of the keyshare to use for signing.
	SigningKeyshareID uuid.UUID
	// Message is the message to sign.
	Message []byte
	// VerifyingKey is the verifying key for the message.
	VerifyingKey []byte
	// UserCommitment is the user commitment for the message.
	UserCommitment *objects.SigningCommitment
	// AdaptorPublicKey is the adaptor public key for the message.
	AdaptorPublicKey []byte
}

type SigningJobWithPregeneratedNonce struct {
	SigningJob
	Round1Packages map[string]objects.SigningCommitment
}

// NewSigningJob creates a new signing job from signing job proto and the keyshare.
func NewSigningJob(keyshare *ent.SigningKeyshare, proto *pbspark.SigningJob, prevOutput *wire.TxOut, adaptorPublicKey []byte) (*SigningJob, *wire.MsgTx, error) {
	if keyshare == nil {
		return nil, nil, errors.New("keyshare cannot be nil")
	}
	if proto == nil {
		return nil, nil, errors.New("proto cannot be nil")
	}
	if prevOutput == nil {
		return nil, nil, errors.New("prevOutput cannot be nil")
	}

	verifyingKey, err := common.AddPublicKeys(proto.SigningPublicKey, keyshare.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	tx, err := common.TxFromRawTxBytes(proto.RawTx)
	if err != nil {
		return nil, nil, err
	}

	totalOutputValue := int64(0)
	for _, out := range tx.TxOut {
		if out.Value < 0 {
			return nil, nil, ErrNegativeOutputValue
		}
		if totalOutputValue > math.MaxInt64-out.Value {
			return nil, nil, ErrTotalOutputValueGreaterThanMaxInt64
		}
		totalOutputValue += out.Value
	}

	if totalOutputValue > prevOutput.Value {
		return nil, nil, fmt.Errorf("%w: totalOutputValue: %d, prevOutputValue: %d", ErrTotalOutputValueGreaterThanPrevOutputValue, totalOutputValue, prevOutput.Value)
	}

	txSigHash, err := common.SigHashFromTx(tx, 0, prevOutput)
	if err != nil {
		return nil, nil, err
	}
	userCommitment := objects.SigningCommitment{}
	err = userCommitment.UnmarshalProto(proto.SigningNonceCommitment)
	if err != nil {
		return nil, nil, err
	}
	job := &SigningJob{
		JobID:             uuid.New().String(),
		SigningKeyshareID: keyshare.ID,
		Message:           txSigHash,
		VerifyingKey:      verifyingKey,
		UserCommitment:    &userCommitment,
		AdaptorPublicKey:  adaptorPublicKey,
	}

	return job, tx, nil
}

// SigningKeyshareIDsFromSigningJobs returns the IDs of the keyshares used for signing.
func SigningKeyshareIDsFromSigningJobs(jobs []*SigningJob) []uuid.UUID {
	ids := make([]uuid.UUID, len(jobs))
	for i, job := range jobs {
		ids[i] = job.SigningKeyshareID
	}
	return ids
}

// SignFrost performs the Frost signing.
// It will perform two rounds internally, and collect the final signature along with signing commitments.
// This is for 1 + (t, n) signing scheme, on the group side.
// The result for this function is not the final signature, the user side needs to perform their signing part
// and then aggregate the results to have the final signature.
//
// Args:
//   - ctx: context
//   - config: the config
//   - signingKeyshareID: the keyshare ID to use for signing.
//   - message: the message to sign
//   - verifyingKey: the combined verifying key, this will be user's public key + operator's public key
//   - userCommitment: the user commitment
//
// Returns:
//   - *SigningResult: the result of the signing, containing the signature shares and signing commitments
func SignFrost(
	ctx context.Context,
	config *so.Config,
	jobs []*SigningJob,
) ([]*SigningResult, error) {
	return SignFrostInternal(ctx, config, jobs, ent.GetKeyPackages, &SparkServiceClientFactoryImpl{})
}

type KeyPackageProvider func(ctx context.Context, config *so.Config, keyshareIDs []uuid.UUID) (map[uuid.UUID]*pbfrost.KeyPackage, error)

func SignFrostInternal(ctx context.Context, config *so.Config, jobs []*SigningJob, getKeyPackages KeyPackageProvider, sparkServiceClientFactory SparkServiceClientFactory) ([]*SigningResult, error) {
	selection := OperatorSelection{Option: OperatorSelectionOptionThreshold, Threshold: int(config.Threshold)}
	signingKeyshareIDs := SigningKeyshareIDsFromSigningJobs(jobs)
	signingKeyshares, err := getKeyPackages(ctx, config, signingKeyshareIDs)
	if err != nil {
		return nil, err
	}

	for _, id := range signingKeyshareIDs {
		if _, exists := signingKeyshares[id]; !exists {
			return nil, fmt.Errorf("keyshare %s not found", id.String())
		}
	}

	publicKeyMap := make(map[string][]byte)
	for _, id := range signingKeyshareIDs {
		publicKeyMap[id.String()] = signingKeyshares[id].PublicKey
	}
	round1, err := frostRound1(ctx, config, signingKeyshareIDs, &selection, publicKeyMap, 1, sparkServiceClientFactory)
	if err != nil {
		return nil, err
	}

	round2, err := frostRound2(ctx, config, jobs, round1, &selection, sparkServiceClientFactory)
	if err != nil {
		return nil, err
	}

	round1Array := common.MapOfArrayToArrayOfMap(round1)
	return prepareResults(config, &selection, jobs, signingKeyshares, round1Array, round2)
}

func SignFrostWithPregeneratedNonce(ctx context.Context, config *so.Config, jobs []*SigningJobWithPregeneratedNonce) ([]*SigningResult, error) {
	return SignFrostWithPregeneratedNonceInternal(ctx, config, jobs, ent.GetKeyPackages, &SparkServiceClientFactoryImpl{})
}

func SignFrostWithPregeneratedNonceInternal(ctx context.Context, config *so.Config, jobs []*SigningJobWithPregeneratedNonce, getKeyPackages KeyPackageProvider, sparkServiceClientFactory SparkServiceClientFactory) ([]*SigningResult, error) {
	signingJobs := make([]*SigningJob, len(jobs))
	for i, job := range jobs {
		signingJobs[i] = &job.SigningJob
	}
	signingKeyshareIDs := SigningKeyshareIDsFromSigningJobs(signingJobs)
	signingKeyshares, err := getKeyPackages(ctx, config, signingKeyshareIDs)
	if err != nil {
		return nil, err
	}

	round1Array := make([]map[string]objects.SigningCommitment, len(jobs))
	for i, job := range jobs {
		round1Array[i] = job.Round1Packages
	}
	round1 := common.ArrayOfMapToMapOfArray(round1Array)

	operatorIDs := make([]string, 0, len(round1))
	for operatorID := range round1 {
		operatorIDs = append(operatorIDs, operatorID)
	}
	selection, err := NewPreSelectedOperatorSelection(config, operatorIDs)
	if err != nil {
		return nil, err
	}

	round2, err := frostRound2(ctx, config, signingJobs, round1, selection, sparkServiceClientFactory)
	if err != nil {
		return nil, err
	}
	return prepareResults(config, selection, signingJobs, signingKeyshares, round1Array, round2)
}

func prepareResults(
	config *so.Config,
	selection *OperatorSelection,
	jobs []*SigningJob,
	signingKeyshares map[uuid.UUID]*pbfrost.KeyPackage,
	round1Array []map[string]objects.SigningCommitment,
	round2 map[string]map[string][]byte,
) ([]*SigningResult, error) {
	results := make([]*SigningResult, len(jobs))
	signingParticipants, err := selection.OperatorList(config)
	if err != nil {
		return nil, err
	}
	for i, job := range jobs {
		allPublicShares := signingKeyshares[job.SigningKeyshareID].PublicShares
		publicShares := make(map[string][]byte)
		keyshareOwnerIdentifiers := make([]string, 0)
		for i := range allPublicShares {
			keyshareOwnerIdentifiers = append(keyshareOwnerIdentifiers, i)
		}
		for _, participant := range signingParticipants {
			publicShares[participant.Identifier] = allPublicShares[participant.Identifier]
		}

		results[i] = &SigningResult{
			JobID:                    job.JobID,
			Message:                  job.Message,
			SignatureShares:          round2[job.JobID],
			SigningCommitments:       round1Array[i],
			PublicKeys:               publicShares,
			KeyshareOwnerIdentifiers: keyshareOwnerIdentifiers,
			KeyshareThreshold:        signingKeyshares[job.SigningKeyshareID].MinSigners,
		}
	}

	return results, nil
}

// GetSigningCommitments gets the signing commitments for the given keyshare ids.
func GetSigningCommitments(ctx context.Context, config *so.Config, keyshareIDs []uuid.UUID, count uint32) (map[string][]objects.SigningCommitment, error) {
	return GetSigningCommitmentsInternal(ctx, config, keyshareIDs, ent.GetKeyPackages, count, &SparkServiceClientFactoryImpl{})
}

func GetSigningCommitmentsInternal(ctx context.Context, config *so.Config, keyshareIDs []uuid.UUID, getKeyPackages KeyPackageProvider, count uint32, sparkServiceClientFactory SparkServiceClientFactory) (map[string][]objects.SigningCommitment, error) {
	if count == 0 {
		return nil, errors.New("count cannot be 0")
	}

	selection := OperatorSelection{Option: OperatorSelectionOptionThreshold, Threshold: int(config.Threshold)}
	signingKeyshares, err := getKeyPackages(ctx, config, keyshareIDs)
	if err != nil {
		return nil, err
	}
	publicKeyMap := make(map[string][]byte)
	for _, id := range keyshareIDs {
		publicKeyMap[id.String()] = signingKeyshares[id].PublicKey
	}
	round1, err := frostRound1(ctx, config, keyshareIDs, &selection, make(map[string][]byte, count), count, sparkServiceClientFactory)
	if err != nil {
		return nil, err
	}
	return round1, nil
}
