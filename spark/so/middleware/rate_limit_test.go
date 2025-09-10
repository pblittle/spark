package middleware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lightsparkdev/spark/so/knobs"
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

func (s *testMemoryStore) Get(ctx context.Context, key string) (tokens uint64, remaining uint64, err error) {
	return 0, 0, nil
}

func (s *testMemoryStore) Set(ctx context.Context, key string, tokens uint64, interval time.Duration) error {
	return nil
}

func (s *testMemoryStore) Take(ctx context.Context, key string) (tokens uint64, remaining uint64, reset uint64, ok bool, err error) {
	return 0, 0, 0, s.ok, nil
}

type conditionalErrorStore struct {
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	maxTokens uint64
	remaining uint64
}

func (s *conditionalErrorStore) Get(ctx context.Context, key string) (tokens uint64, remaining uint64, err error) {
	if bucket, exists := s.buckets[key]; exists {
		return bucket.maxTokens, bucket.remaining, nil
	}
	return 0, 0, fmt.Errorf("key not found: %s", key)
}

func (s *conditionalErrorStore) Set(ctx context.Context, key string, tokens uint64, interval time.Duration) error {
	s.buckets[key] = &tokenBucket{
		maxTokens: tokens,
		remaining: tokens,
	}
	return nil
}

func (s *conditionalErrorStore) Take(ctx context.Context, key string) (tokens uint64, remaining uint64, reset uint64, ok bool, err error) {
	bucket, exists := s.buckets[key]
	if !exists {
		return 0, 0, 0, false, fmt.Errorf("bucket not found")
	}

	if bucket.remaining > 0 {
		bucket.remaining--
		return bucket.maxTokens, bucket.remaining, 0, true, nil
	}

	return bucket.maxTokens, 0, 0, false, nil
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

		ctx := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))
		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx, "request", info, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
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
			resp, err := interceptor(t.Context(), "request", info, handler)
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

		ctx := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
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

		ctx1 := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))
		ctx2 := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
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
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

		_, err = interceptor(ctx2, "request", info, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
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
		ctx := metadata.NewIncomingContext(t.Context(), md)
		ctx2 := metadata.NewIncomingContext(t.Context(), md2)

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
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

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
		ctx := metadata.NewIncomingContext(t.Context(), md)

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
		ctx := metadata.NewIncomingContext(t.Context(), md)

		// Should use "10.0.0.1" (second-to-last) for rate limiting
		resp, err := interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		resp, err = interceptor(ctx, "request", info, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		_, err = interceptor(ctx, "request", info, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

		// Test just switching the second-to-last IP to ensure it isn't rate
		// limited initially even though the prior IP in that position was
		// limited, but then it is rate limited after the limit is exceeded.
		md2 := metadata.New(map[string]string{
			"x-forwarded-for": "192.168.1.100, 10.0.0.2, 172.16.0.1",
		})
		ctx2 := metadata.NewIncomingContext(t.Context(), md2)

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

	t.Run("knob values enforced", func(t *testing.T) {
		config := &RateLimiterConfig{
			Window:      time.Second,
			MaxRequests: 2,
			Methods:     []string{"/test.Service/TestMethod"},
		}

		mockKnobsMap := map[string]float64{
			knobs.KnobRateLimitPeriod:                                5,  // period expressed in seconds
			knobs.KnobRateLimitMethods + "@/test.Service/Enable":     1,  // > 0: Enable rate limiting
			knobs.KnobRateLimitMethods + "@/test.Service/Disable":    0,  // = 0: Disable rate limiting
			knobs.KnobRateLimitMethods + "@/test.Service/TestMethod": 0,  // = 0: Disable rate limiting (override config)
			knobs.KnobRateLimitMethods + "@/test.Service/Follow":     -1, // < 0: Follow configuration (not in config Methods list)
		}
		mockKnobs := knobs.NewFixedKnobs(mockKnobsMap)

		tests := []struct {
			name          string
			method        string
			expectedError bool
			requests      int
		}{
			{
				name:          "knob value > 0 enables rate limiting",
				method:        "/test.Service/Enable",
				expectedError: false,
				requests:      2, // Should succeed for first 2 requests
			},
			{
				name:          "knob value > 0 rate limits after max requests",
				method:        "/test.Service/Enable",
				expectedError: true,
				requests:      3, // Third request should fail
			},
			{
				name:          "knob value = 0 disables rate limiting",
				method:        "/test.Service/Disable",
				expectedError: false,
				requests:      5, // Should allow unlimited requests
			},
			{
				name:          "knob value = 0 overrides config method",
				method:        "/test.Service/TestMethod",
				expectedError: false,
				requests:      5, // Should allow unlimited requests despite being in config
			},
			{
				name:          "knob value < 0 follows configuration",
				method:        "/test.Service/Follow",
				expectedError: false,
				requests:      5, // Should allow unlimited requests (not in config)
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				rateLimiter, err := NewRateLimiter(config, WithKnobs(mockKnobs))
				require.NoError(t, err)

				interceptor := rateLimiter.UnaryServerInterceptor()
				handler := func(_ context.Context, _ any) (any, error) {
					return "ok", nil
				}

				ctx := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
					"x-forwarded-for": "1.2.3.4",
				}))

				info := &grpc.UnaryServerInfo{FullMethod: tt.method}

				var resp any
				for i := 0; i < tt.requests-1; i++ {
					resp, err = interceptor(ctx, "request", info, handler)
					require.NoError(t, err)
					require.Equal(t, "ok", resp)
				}
				resp, err = interceptor(ctx, "request", info, handler)
				if tt.expectedError {
					require.ErrorContains(t, err, "rate limit exceeded")
					require.Equal(t, codes.ResourceExhausted, status.Code(err))
				} else {
					require.NoError(t, err)
					require.Equal(t, "ok", resp)
				}
			})
		}
	})

	t.Run("per-method max requests knob values are read correctly", func(t *testing.T) {
		config := &RateLimiterConfig{
			MaxRequests: 2,
		}

		mockKnobsMap := map[string]float64{
			knobs.KnobRateLimitLimit + "@/test.Service/Method1": 5,
			knobs.KnobRateLimitLimit + "@/test.Service/Method2": 1,
		}
		mockKnobs := knobs.NewFixedKnobs(mockKnobsMap)

		method1Value := mockKnobs.GetValueTarget(knobs.KnobRateLimitLimit, &(&grpc.UnaryServerInfo{FullMethod: "/test.Service/Method1"}).FullMethod, float64(config.MaxRequests))
		assert.InDelta(t, 5.0, method1Value, 0.001, "Method1 should have custom limit of 5")

		method2Value := mockKnobs.GetValueTarget(knobs.KnobRateLimitLimit, &(&grpc.UnaryServerInfo{FullMethod: "/test.Service/Method2"}).FullMethod, float64(config.MaxRequests))
		assert.InDelta(t, 1.0, method2Value, 0.001, "Method2 should have custom limit of 1")

		methodDefaultValue := mockKnobs.GetValueTarget(knobs.KnobRateLimitLimit, &(&grpc.UnaryServerInfo{FullMethod: "/test.Service/Default"}).FullMethod, float64(config.MaxRequests))
		assert.InDelta(t, 2.0, methodDefaultValue, 0.001, "Default method should use config default of 2")
	})

	t.Run("per-method limits allow dynamic updates to limits", func(t *testing.T) {
		store := &conditionalErrorStore{
			buckets: make(map[string]*tokenBucket),
		}

		knobValues := map[string]float64{
			knobs.KnobRateLimitLimit + "@/test.Service/Method1": 5,
			knobs.KnobRateLimitLimit + "@/test.Service/Method2": 1,
		}
		mockKnobs := knobs.NewFixedKnobs(knobValues)

		config := &RateLimiterConfig{
			Window:      time.Second,
			MaxRequests: 2,
			Methods:     []string{"/test.Service/Method1", "/test.Service/Method2", "/test.Service/Method4"},
		}

		clock := &testClock{Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}

		rateLimiter, err := NewRateLimiter(config, WithKnobs(mockKnobs), WithStore(store), WithClock(clock))
		require.NoError(t, err)

		interceptor := rateLimiter.UnaryServerInterceptor()
		handler := func(_ context.Context, _ any) (any, error) {
			return "ok", nil
		}

		ctx := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "1.2.3.4",
		}))

		// Test Method1 with custom limit of 5 requests
		info1 := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method1"}

		// First 5 requests should succeed
		for i := 0; i < 5; i++ {
			resp, err := interceptor(ctx, "request", info1, handler)
			require.NoError(t, err, "Method1 request %d should succeed", i+1)
			assert.Equal(t, "ok", resp)
		}

		// 6th request should fail due to rate limit
		_, err = interceptor(ctx, "request", info1, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

		// But if we dynamically update the knob value for this method, it
		// should work again.
		knobValues[knobs.KnobRateLimitLimit+"@/test.Service/Method1"] = 50
		clock.Time = clock.Time.Add(2 * time.Second)
		resp, err := interceptor(ctx, "request", info1, handler)
		require.NoError(t, err, "Method1 request should succeed after knob update")
		assert.Equal(t, "ok", resp)

		// Test Method2 with custom limit of 1 request
		ctx2 := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "5.6.7.8",
		}))
		info2 := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method2"}

		// First request should succeed
		resp, err = interceptor(ctx2, "request", info2, handler)
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)

		// 2nd request should fail due to rate limit
		_, err = interceptor(ctx2, "request", info2, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

		// Test Method3 without custom knob - should use default limit of 2
		ctx3 := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "9.10.11.12",
		}))
		info3 := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method3"}

		// Need to add Method3 to the methods list and create a new rate limiter
		config3 := &RateLimiterConfig{
			Window:      time.Second,
			MaxRequests: 2,
			Methods:     []string{"/test.Service/Method3"},
		}

		rateLimiter3, err := NewRateLimiter(config3, WithKnobs(mockKnobs), WithStore(store), WithClock(clock))
		require.NoError(t, err)
		interceptor3 := rateLimiter3.UnaryServerInterceptor()

		// First 2 requests should succeed (default limit)
		for i := 0; i < 2; i++ {
			resp, err := interceptor3(ctx3, "request", info3, handler)
			require.NoError(t, err, "Method3 request %d should succeed", i+1)
			assert.Equal(t, "ok", resp)
		}

		// 3rd request should fail due to rate limit
		_, err = interceptor3(ctx3, "request", info3, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))

		ctx4 := metadata.NewIncomingContext(t.Context(), metadata.New(map[string]string{
			"x-forwarded-for": "90.100.110.120",
		}))
		info4 := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method4"}

		config4 := &RateLimiterConfig{
			Window:      time.Second,
			MaxRequests: 2,
			Methods:     []string{"/test.Service/Method4"},
		}
		rateLimiter4, err := NewRateLimiter(config4, WithKnobs(mockKnobs), WithStore(store), WithClock(clock))
		require.NoError(t, err)
		interceptor4 := rateLimiter4.UnaryServerInterceptor()

		// Ensure that the special case values work with dynamically set knobs.
		// == 0 disables the rate limit.
		knobValues[knobs.KnobRateLimitLimit+"@/test.Service/Method4"] = 0
		// First 4 requests should succeed because there's no limit.
		for i := 0; i < 4; i++ {
			resp, err := interceptor4(ctx4, "request", info4, handler)
			require.NoError(t, err, "Method4 request %d should succeed", i+1)
			assert.Equal(t, "ok", resp)
		}

		// < 0 uses the default limit.
		// Test Method3 without custom knob - should use default limit of 2
		knobValues[knobs.KnobRateLimitLimit+"@/test.Service/Method4"] = -1
		// First 2 requests should succeed (default limit)
		for i := 0; i < 2; i++ {
			resp, err := interceptor4(ctx4, "request", info4, handler)
			require.NoError(t, err, "Method4 request %d should succeed", i+1)
			assert.Equal(t, "ok", resp)
		}

		// 3rd request should fail due to rate limit
		_, err = interceptor4(ctx4, "request", info4, handler)
		require.ErrorContains(t, err, "rate limit exceeded")
		require.Equal(t, codes.ResourceExhausted, status.Code(err))
	})
}
