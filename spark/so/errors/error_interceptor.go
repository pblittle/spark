package errors

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorMaskingInterceptor masks error messages for internal/unknown error codes
// to avoid leaking sensitive information.
func ErrorMaskingInterceptor(returnDetailedErrors bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		resp, err = handler(ctx, req)
		if statusErr, ok := status.FromError(err); ok && (statusErr.Code() == codes.Internal || statusErr.Code() == codes.Unknown) {
			if returnDetailedErrors || isInternalRPC(info.FullMethod) {
				return resp, status.Errorf(codes.Internal, "Something went wrong. Error: %+v", err)
			}
			return resp, status.Errorf(codes.Internal, "Something went wrong.")
		}
		return resp, err
	}
}

func isInternalRPC(fullMethod string) bool {
	for _, prefix := range []string{
		"/spark_internal.SparkInternalService/",
		"/spark_ssp.SparkSspInternalService/",
		"/spark_token.SparkTokenInternalService/",
	} {
		if strings.HasPrefix(fullMethod, prefix) {
			return true
		}
	}
	return false
}

// ErrorWrappingInterceptor automatically converts any error to a gRPC error using asGRPCError
// to preserve full error context for logging while still returning the appropriate
// gRPC error to callers.
func ErrorWrappingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		return resp, asGRPCError(err)
	}
}

func ErrorWrappingStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		err := handler(srv, ss)
		return asGRPCError(err)
	}
}
