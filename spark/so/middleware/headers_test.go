package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestGetClientIpFromHeader(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		expectedIp string
	}{
		{
			name:       "last ip",
			count:      0,
			expectedIp: "192.168.1.3",
		},
		{
			name:       "middle ip",
			count:      1,
			expectedIp: "192.168.1.2",
		},
		{
			name:       "first ip",
			count:      2,
			expectedIp: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			md := metadata.New(map[string]string{
				"x-forwarded-for": "192.168.1.1,192.168.1.2,192.168.1.3",
			})
			ctx = metadata.NewIncomingContext(ctx, md)
			ip, err := GetClientIpFromHeader(ctx, tt.count)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedIp, ip)
		})
	}
}

func TestGetClientIpFromHeaderErrors(t *testing.T) {
	t.Run("no metadata", func(t *testing.T) {
		ctx := context.Background()
		ip, err := GetClientIpFromHeader(ctx, 0)
		require.ErrorContains(t, err, "no metadata found")
		assert.Empty(t, ip)
	})

	tests := []struct {
		name  string
		count int
	}{
		{
			name:  "too big of a count",
			count: 3,
		},
		{
			name:  "negative count",
			count: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			md := metadata.New(map[string]string{
				"x-forwarded-for": "192.168.1.1,192.168.1.2,192.168.1.3",
			})
			ctx = metadata.NewIncomingContext(ctx, md)

			ip, err := GetClientIpFromHeader(ctx, tt.count)
			require.ErrorContains(t, err, "no client IP found in header")
			assert.Empty(t, ip)
		})
	}
}
