package helper

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/knobs"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type signingCommitmentsKeyType string

const signingCommitmentsKey signingCommitmentsKeyType = "ReservedSigningCommitments"

func SigningCommitmentInterceptor(operatorMap map[string]*so.SigningOperator, knobs *knobs.Knobs) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if knobs.GetValue("spark.so.enable_prefetch_frost_round_1", 0) == 0 {
			return handler(ctx, req)
		}

		signingCommitmentsCount := calculateSigningCommitmentCount(req)
		if signingCommitmentsCount > 0 {
			logger := logging.GetLoggerFromContext(ctx)
			logger.Info("Signing commitment count", "count", signingCommitmentsCount)
			dbTx, err := ent.GetDbFromContext(ctx)
			if err != nil {
				return nil, err
			}

			commitmentsMap := make(map[uint][]*ent.SigningCommitment)
			for _, operator := range operatorMap {
				idx := uint(operator.ID)
				commitments, err := ent.GetUnusedSigningCommitments(ctx, dbTx, uint32(signingCommitmentsCount), idx)
				if err == nil {
					commitmentsMap[idx] = commitments
				}
			}
			err = dbTx.Commit()
			if err != nil {
				return nil, err
			}
			ctx = injectSigningCommitments(ctx, commitmentsMap)
		}

		return handler(ctx, req)
	}
}

func calculateSigningCommitmentCount(req any) int {
	protobufMessage := req.(proto.Message)
	return CountMessageTypeInProto(protobufMessage, "spark.SigningJob")
}

func injectSigningCommitments(ctx context.Context, commitmentsMap map[uint][]*ent.SigningCommitment) context.Context {
	ctx = context.WithValue(ctx, signingCommitmentsKey, commitmentsMap)
	return ctx
}

func GetSigningCommitmentsFromContext(ctx context.Context, count int, operatorIndex uint) ([]*ent.SigningCommitment, error) {
	commitmentsMapValue := ctx.Value(signingCommitmentsKey)
	if commitmentsMapValue == nil {
		return nil, fmt.Errorf("no signing commitments found in context")
	}
	commitmentsMap := commitmentsMapValue.(map[uint][]*ent.SigningCommitment)
	commitments := commitmentsMap[operatorIndex]
	if len(commitments) < count {
		return nil, fmt.Errorf("not enough signing commitments for operator index %d", operatorIndex)
	}
	newCommitments := commitments[count:]
	commitmentsMap[operatorIndex] = newCommitments
	return commitments[:count], nil
}
