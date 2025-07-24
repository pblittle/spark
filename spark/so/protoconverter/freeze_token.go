package protoconverter

import (
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
)

func SparkFreezeTokensRequestFromTokenProto(req *tokenpb.FreezeTokensRequest) *sparkpb.FreezeTokensRequest {
	if req == nil {
		return nil
	}
	return &sparkpb.FreezeTokensRequest{
		FreezeTokensPayload: &sparkpb.FreezeTokensPayload{
			OwnerPublicKey:            req.FreezeTokensPayload.OwnerPublicKey,
			TokenPublicKey:            req.FreezeTokensPayload.TokenPublicKey,
			TokenIdentifier:           req.FreezeTokensPayload.TokenIdentifier,
			IssuerProvidedTimestamp:   req.FreezeTokensPayload.IssuerProvidedTimestamp,
			OperatorIdentityPublicKey: req.FreezeTokensPayload.OperatorIdentityPublicKey,
			ShouldUnfreeze:            req.FreezeTokensPayload.ShouldUnfreeze,
		},
		IssuerSignature: req.IssuerSignature,
	}
}

func TokenProtoFreezeTokensRequestFromSpark(req *sparkpb.FreezeTokensRequest) *tokenpb.FreezeTokensRequest {
	if req == nil {
		return nil
	}
	return &tokenpb.FreezeTokensRequest{
		FreezeTokensPayload: &tokenpb.FreezeTokensPayload{
			Version:                   0,
			OwnerPublicKey:            req.FreezeTokensPayload.OwnerPublicKey,
			TokenPublicKey:            req.FreezeTokensPayload.TokenPublicKey,
			TokenIdentifier:           req.FreezeTokensPayload.TokenIdentifier,
			IssuerProvidedTimestamp:   req.FreezeTokensPayload.IssuerProvidedTimestamp,
			OperatorIdentityPublicKey: req.FreezeTokensPayload.OperatorIdentityPublicKey,
			ShouldUnfreeze:            req.FreezeTokensPayload.ShouldUnfreeze,
		},
		IssuerSignature: req.IssuerSignature,
	}
}

func SparkFreezeTokensResponseFromTokenProto(res *tokenpb.FreezeTokensResponse) *sparkpb.FreezeTokensResponse {
	if res == nil {
		return nil
	}
	return &sparkpb.FreezeTokensResponse{
		ImpactedOutputIds:   res.ImpactedOutputIds,
		ImpactedTokenAmount: res.ImpactedTokenAmount,
	}
}
