package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type testClock struct {
	Time time.Time
}

func (c *testClock) Now() time.Time {
	return c.Time
}

type testMemoryStore struct {
	ok bool
}

func (s *testMemoryStore) Take(ctx context.Context, key string) (tokens uint64, remaining uint64, reset uint64, ok bool, err error) {
	return 0, 0, 0, s.ok, nil
}

func TestRateLimiter(t *testing.T) {
	config := &RateLimiterConfig{
		Window:      time.Second,
		MaxRequests: 2,
		Methods:     []string{"/test.Service/TestMethod"},
	}

	t.Run("basic rate limiting", func(t *testing.T) {
		rateLimiter, err := NewRateLimiter(config)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		ctx := metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))
		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())
	})

	t.Run("method not rate limited", func(t *testing.T) {
		rateLimiter, err := NewRateLimiter(config)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/NotLimited"}

		for i := 0; i < 5; i++ {
			resp, err := interceptor(context.Background(), "request", info, handler)
			require.NoError(t, err)
			assert.Equal(t, "ok", resp)
		}
	})

	t.Run("window expiration", func(t *testing.T) {
		clock := &testClock{Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
		store := &testMemoryStore{ok: true}

		rateLimiter, err := NewRateLimiter(config, WithClock(clock), WithStore(store))
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		ctx := metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))

		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		// Simulate rate limit exceeding
		store.ok = false

		_, err = interceptor(ctx, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())

		// Now simulate time passing which resets the rate limit
		clock.Time = clock.Time.Add(2 * time.Second)
		store.ok = true

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})

	t.Run("different clients", func(t *testing.T) {
		rateLimiter, err := NewRateLimiter(config)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		ctx1 := metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))
		ctx2 := metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
			"x-forwarded-for": "5.6.7.8",
		}))

		resp, err := interceptor(ctx1, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx1, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx2, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx2, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx1, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())

		_, err = interceptor(ctx2, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())
	})

	t.Run("multiple x-forwarded-for headers", func(t *testing.T) {
		rateLimiter, err := NewRateLimiter(config)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		// Create metadata with multiple x-forwarded-for headers
		md := metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.10.11.12",
		})
		md2 := metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.10.11.13",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)
		ctx2 := metadata.NewIncomingContext(context.Background(), md2)

		// Should use the last IP (9.10.11.12) for rate limiting, so exhaust the
		// resources with the first two requests, but then make sure the third
		// request goes through.
		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())

		resp, err = interceptor(ctx2, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})

	t.Run("x-real-ip ignored", func(t *testing.T) {
		rateLimiter, err := NewRateLimiter(config)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		// Create metadata with only x-real-ip (no x-forwarded-for)
		md := metadata.New(map[string]string{
			"x-real-ip": "1.2.3.4",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		// Should not rate limit since x-real-ip is ignored
		for i := 0; i < 5; i++ {
			resp, err := interceptor(ctx, "request", info, handler)
			require.NoError(t, err)
			assert.Equal(t, "ok", resp)
		}
	})

	t.Run("custom x-forwarded-for client IP position", func(t *testing.T) {
		// Configure rate limiter to use the second-to-last IP (position 1)
		configWithCustomPosition := &RateLimiterConfig{
			Window:              time.Second,
			MaxRequests:         2,
			Methods:             []string{"/test.Service/TestMethod"},
			XffClientIpPosition: 1,
		}

		rateLimiter, err := NewRateLimiter(configWithCustomPosition)
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/TestMethod"}

		// Create metadata with multiple x-forwarded-for headers
		// Format: "client,proxy1,proxy2" - using position 1 should use "proxy1"
		md := metadata.New(map[string]string{
			"x-forwarded-for": "192.168.1.100, 10.0.0.1, 172.16.0.1",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		// Should use "10.0.0.1" (second-to-last) for rate limiting
		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())

		// Test just switching the second-to-last IP to ensure it isn't rate
		// limited initially even though the prior IP in that position was
		// limited, but then it is rate limited after the limit is exceeded.
		md2 := metadata.New(map[string]string{
			"x-forwarded-for": "192.168.1.100, 10.0.0.2, 172.16.0.1",
		})
		ctx2 := metadata.NewIncomingContext(context.Background(), md2)

		resp, err = interceptor(ctx2, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx2, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx2, "request", info, handler)
		require.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, "rate limit exceeded", status.Convert(err).Message())
	})
}
