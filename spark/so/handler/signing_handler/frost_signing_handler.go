package signing_handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pb "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/objects"
)

type FrostSigningHandler struct {
	config *so.Config
}

func NewFrostSigningHandler(config *so.Config) *FrostSigningHandler {
	return &FrostSigningHandler{config: config}
}

func (h *FrostSigningHandler) FrostRound1(ctx context.Context, req *pb.FrostRound1Request) (*pb.FrostRound1Response, error) {
	uuids := make([]uuid.UUID, len(req.KeyshareIds))
	for i, id := range req.KeyshareIds {
		uuid, err := uuid.Parse(id)
		if err != nil {
			return nil, err
		}
		uuids[i] = uuid
	}

	keyPackages, err := ent.GetKeyPackages(ctx, h.config, uuids)
	if err != nil {
		return nil, err
	}
	badKeyshares := []string{}
	for id, kp := range keyPackages {
		if !bytes.Equal(kp.PublicKey, req.PublicKeys[id.String()]) {
			badKeyshares = append(badKeyshares, id.String())
		}
	}
	logger := logging.GetLoggerFromContext(ctx)
	if len(badKeyshares) != 0 {
		logger.Warn("Detected bad keyshares.", "numBadKeyshares", len(badKeyshares), "badKeyshares", badKeyshares)
	}

	keyPackagesArray := make([]*pbfrost.KeyPackage, 0)
	for _, uuid := range uuids {
		keyPackagesArray = append(keyPackagesArray, keyPackages[uuid])
	}

	frostConn, err := common.NewGRPCConnectionWithoutTLS(h.config.SignerAddress, nil)
	if err != nil {
		return nil, err
	}
	defer frostConn.Close()

	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	count := req.Count
	if count == 0 {
		count = 1
	}

	commitments := make([]*pbcommon.SigningCommitment, 0)
	for range count {
		round1Response, err := frostClient.FrostNonce(ctx, &pbfrost.FrostNonceRequest{
			KeyPackages: keyPackagesArray,
		})
		if err != nil {
			return nil, err
		}

		db, err := ent.GetDbFromContext(ctx)
		if err != nil {
			return nil, err
		}

		entSigningNonces := make([]*ent.SigningNonceCreate, 0, len(round1Response.Results))

		for _, result := range round1Response.Results {
			nonce := objects.SigningNonce{}
			err = nonce.UnmarshalProto(result.Nonces)
			if err != nil {
				return nil, err
			}
			commitment := objects.SigningCommitment{}
			err = commitment.UnmarshalProto(result.Commitments)
			if err != nil {
				return nil, err
			}

			entSigningNonces = append(
				entSigningNonces,
				db.SigningNonce.Create().
					SetNonce(nonce.MarshalBinary()).
					SetNonceCommitment(commitment.MarshalBinary()),
			)
		}

		_, err = db.SigningNonce.CreateBulk(entSigningNonces...).Save(ctx)
		if err != nil {
			return nil, err
		}

		for _, result := range round1Response.Results {
			commitments = append(commitments, result.Commitments)
		}
	}

	return &pb.FrostRound1Response{
		SigningCommitments: commitments,
	}, nil
}

// FrostRound2 handles FROST signing.
func (h *FrostSigningHandler) FrostRound2(ctx context.Context, req *pb.FrostRound2Request) (*pb.FrostRound2Response, error) {
	// Fetch key packages in one call.
	uuids := make([]uuid.UUID, len(req.SigningJobs))
	for i, job := range req.SigningJobs {
		uuid, err := uuid.Parse(job.KeyshareId)
		if err != nil {
			return nil, err
		}
		uuids[i] = uuid
	}

	keyPackages, err := ent.GetKeyPackages(ctx, h.config, uuids)
	if err != nil {
		return nil, err
	}

	// Fetch nonces in one call.
	commitments := make([]objects.SigningCommitment, len(req.SigningJobs))
	for i, job := range req.SigningJobs {
		commitments[i] = objects.SigningCommitment{}
		err = commitments[i].UnmarshalProto(job.Commitments[h.config.Identifier])
		if err != nil {
			return nil, err
		}
	}
	nonces, err := ent.GetSigningNonces(ctx, h.config, commitments)
	if err != nil {
		return nil, err
	}

	signingJobProtos := make([]*pbfrost.FrostSigningJob, 0)

	for _, job := range req.SigningJobs {
		keyshareID, err := uuid.Parse(job.KeyshareId)
		if err != nil {
			return nil, err
		}
		commitment := objects.SigningCommitment{}
		err = commitment.UnmarshalProto(job.Commitments[h.config.Identifier])
		if err != nil {
			return nil, err
		}
		nonceEnt := nonces[commitment.Key()]
		// TODO(zhenlu): Add a test for this (LIG-7596).
		if len(nonceEnt.Message) > 0 {
			if !bytes.Equal(nonceEnt.Message, job.Message) {
				return nil, fmt.Errorf("this signing nonce is already used for a different message %s, cannot use it for this message %s", hex.EncodeToString(nonceEnt.Message), hex.EncodeToString(job.Message))
			}
		} else {
			_, err = nonceEnt.Update().SetMessage(job.Message).Save(ctx)
			if err != nil {
				return nil, err
			}
		}
		nonceObject := objects.SigningNonce{}
		err = nonceObject.UnmarshalBinary(nonceEnt.Nonce)
		if err != nil {
			return nil, err
		}
		nonceProto, err := nonceObject.MarshalProto()
		if err != nil {
			return nil, err
		}
		signingJobProto := &pbfrost.FrostSigningJob{
			JobId:            job.JobId,
			Message:          job.Message,
			KeyPackage:       keyPackages[keyshareID],
			VerifyingKey:     job.VerifyingKey,
			Nonce:            nonceProto,
			Commitments:      job.Commitments,
			UserCommitments:  job.UserCommitments,
			AdaptorPublicKey: job.AdaptorPublicKey,
		}
		signingJobProtos = append(signingJobProtos, signingJobProto)
	}

	frostConn, err := common.NewGRPCConnectionWithoutTLS(h.config.SignerAddress, nil)
	if err != nil {
		return nil, err
	}
	defer frostConn.Close()
	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	round2Request := &pbfrost.SignFrostRequest{
		SigningJobs: signingJobProtos,
		Role:        pbfrost.SigningRole_STATECHAIN,
	}
	round2Response, err := frostClient.SignFrost(ctx, round2Request)
	if err != nil {
		return nil, err
	}

	return &pb.FrostRound2Response{
		Results: round2Response.Results,
	}, nil
}
