package errors

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	msg   = "message with sensitive data"
	okVal = "ok"
)

var (
	grpcErr    = status.Errorf(codes.Internal, msg)
	errHandler = func(_ context.Context, _ any) (any, error) {
		return nil, grpcErr
	}
)

func TestErrorInterceptor_NoError_ReturnsValue(t *testing.T) {
	serverInfo := &grpc.UnaryServerInfo{FullMethod: "/spark.SparkService/SomeMethod"}
	okHandler := func(_ context.Context, _ any) (any, error) {
		return okVal, nil
	}

	got, err := ErrorMaskingInterceptor(true)(context.Background(), nil, serverInfo, okHandler)

	require.NoError(t, err)
	assert.Equal(t, okVal, got)
}

func TestInternalErrorDetailMasking(t *testing.T) {
	tests := []struct {
		name           string
		detailedErrors bool
		fullMethod     string
		wantDetails    bool
	}{
		{
			name:           "mask details if detailedErrors disabled",
			detailedErrors: false,
			fullMethod:     "/spark.SparkService/SomeMethod",
			wantDetails:    false,
		},
		{
			name:           "show details if detailedErrors enabled",
			detailedErrors: true,
			fullMethod:     "/spark.SparkService/SomeMethod",
			wantDetails:    true,
		},
		{
			name:           "show details for internal service",
			detailedErrors: true,
			fullMethod:     "/spark_internal.SparkInternalService/SomeMethod",
			wantDetails:    true,
		},
		{
			name:           "show details for internal service even if detailedErrors disabled",
			detailedErrors: false,
			fullMethod:     "/spark_internal.SparkInternalService/SomeMethod",
			wantDetails:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverInfo := &grpc.UnaryServerInfo{FullMethod: tt.fullMethod}
			_, err := ErrorMaskingInterceptor(tt.detailedErrors)(context.Background(), nil, serverInfo, errHandler)
			require.Error(t, err)

			if tt.wantDetails {
				require.ErrorContains(t, err, msg)
			} else {
				require.NotContains(t, err.Error(), msg)
			}
		})
	}
}

func TestAsGRPCError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantErr     bool
		wantErrCode codes.Code
	}{
		{
			name:        "no error returns response and nil",
			err:         nil,
			wantErr:     false,
			wantErrCode: codes.OK,
		},
		{
			name:        "with error returns response and wrapped error",
			err:         fmt.Errorf("test error"),
			wantErr:     true,
			wantErrCode: codes.Internal,
		},
		{
			name:        "with custom error returns response and custom error",
			err:         &fakeError{message: "custom error", grpcErr: status.Error(codes.InvalidArgument, "custom")},
			wantErr:     true,
			wantErrCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := asGRPCError(tt.err)

			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantErrCode, status.Convert(err).Code())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAsGrpcError_WithGRPCError_PropagatesErrorCode(t *testing.T) {
	abortedErr := AbortedError(fmt.Errorf("inner aborted error"))
	wrappedErr := fmt.Errorf("wrapped error: %w", abortedErr)
	err := asGRPCError(wrappedErr)
	require.Error(t, err)
	assert.Equal(t, codes.Aborted, status.Convert(err).Code())
	assert.Equal(t, "wrapped error: inner aborted error", err.Error())
}

func TestInvalidUserInputErrorf(t *testing.T) {
	err := InvalidUserInputErrorf("invalid input: %s, value: %d", "field", 42)

	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Equal(t, "invalid input: field, value: 42", st.Message())
}

func TestFailedPreconditionErrorf(t *testing.T) {
	err := FailedPreconditionErrorf("precondition failed: %s, state: %s", "operation", "pending")

	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Equal(t, "precondition failed: operation, state: pending", st.Message())
}

func TestNotFoundErrorf(t *testing.T) {
	err := NotFoundErrorf("resource not found: %s with id %d", "user", 123)

	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Equal(t, "resource not found: user with id 123", st.Message())
}

func TestUnavailableErrorf(t *testing.T) {
	err := UnavailableErrorf("service unavailable: %s, retry after %d seconds", "database", 30)

	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, "service unavailable: database, retry after 30 seconds", st.Message())
}

func TestToGRPCError_NilError_ReturnsNil(t *testing.T) {
	require.NoError(t, toGRPCError(nil))
}

func TestToGRPCError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantErrCode codes.Code
		wantMessage string
	}{
		{
			name:        "regular error returns internal error",
			err:         fmt.Errorf("test error"),
			wantErrCode: codes.Internal,
			wantMessage: "test error",
		},
		{
			name:        "custom error returns its gRPC error",
			err:         &fakeError{message: "custom", grpcErr: status.Error(codes.InvalidArgument, "custom grpc")},
			wantErrCode: codes.InvalidArgument,
			wantMessage: "custom grpc",
		},
		{
			name:        "existing grpcError returns same error",
			err:         InvalidUserInputErrorf("not found"),
			wantErrCode: codes.InvalidArgument,
			wantMessage: "not found",
		},
		{
			name:        "not found error returns not found code",
			err:         NotFoundErrorf("resource not found"),
			wantErrCode: codes.NotFound,
			wantMessage: "resource not found",
		},
		{
			name:        "failed precondition error returns failed precondition code",
			err:         FailedPreconditionErrorf("precondition failed"),
			wantErrCode: codes.FailedPrecondition,
			wantMessage: "precondition failed",
		},
		{
			name:        "unavailable error returns unavailable code",
			err:         UnavailableErrorf("service unavailable"),
			wantErrCode: codes.Unavailable,
			wantMessage: "service unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := toGRPCError(tt.err)

			require.Error(t, err)
			st := status.Convert(err)
			assert.Equal(t, tt.wantErrCode, st.Code())
			assert.Equal(t, tt.wantMessage, st.Message())
		})
	}
}

// fakeError is an Error interface implementation for testing.
type fakeError struct {
	message string
	grpcErr error
}

func (m *fakeError) Error() string {
	return m.message
}

func (m *fakeError) ToGRPCError() error {
	return m.grpcErr
}
