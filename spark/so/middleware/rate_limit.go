package middleware

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sanitizeKey removes control characters and limits key length
func sanitizeKey(key string) string {
	key = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, key)

	const maxLength = 250
	if len(key) > maxLength {
		key = key[:maxLength]
	}

	return key
}

type Clock interface {
	Now() time.Time
}

type RateLimiterConfig struct {
	Window              time.Duration
	MaxRequests         int
	Methods             []string
	XffClientIpPosition int
}

type RateLimiterConfigProvider interface {
	GetRateLimiterConfig() *RateLimiterConfig
}

type RateLimiter struct {
	config *RateLimiterConfig
	store  MemoryStore
	clock  Clock
}

type RateLimiterOption func(*RateLimiter)

func WithClock(clock Clock) RateLimiterOption {
	return func(r *RateLimiter) {
		r.clock = clock
	}
}

func WithStore(store MemoryStore) RateLimiterOption {
	return func(r *RateLimiter) {
		r.store = store
	}
}

type realClock struct{}

func (c *realClock) Now() time.Time {
	return time.Now()
}

type MemoryStore interface {
	Take(ctx context.Context, key string) (tokens uint64, remaining uint64, reset uint64, ok bool, err error)
}

type realMemoryStore struct {
	store limiter.Store
}

func (s *realMemoryStore) Take(ctx context.Context, key string) (tokens uint64, remaining uint64, reset uint64, ok bool, err error) {
	return s.store.Take(ctx, key)
}

func NewRateLimiter(configOrProvider any, opts ...RateLimiterOption) (*RateLimiter, error) {
	var config *RateLimiterConfig
	switch v := configOrProvider.(type) {
	case *RateLimiterConfig:
		config = v
	case RateLimiterConfigProvider:
		config = v.GetRateLimiterConfig()
	default:
		return nil, fmt.Errorf("invalid config type: %T", configOrProvider)
	}

	defaultStore, err := memorystore.New(&memorystore.Config{
		Tokens:   uint64(config.MaxRequests),
		Interval: config.Window,
	})
	if err != nil {
		return nil, err
	}

	rateLimiter := &RateLimiter{
		config: config,
		store:  &realMemoryStore{store: defaultStore},
		clock:  &realClock{},
	}

	for _, opt := range opts {
		opt(rateLimiter)
	}

	return rateLimiter, nil
}

func (r *RateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		shouldLimit := slices.Contains(r.config.Methods, info.FullMethod)

		if !shouldLimit {
			return handler(ctx, req)
		}

		ip, err := GetClientIpFromHeader(ctx, r.config.XffClientIpPosition)
		if err != nil {
			return handler(ctx, req)
		}

		key := sanitizeKey(fmt.Sprintf("rl:%s:%s", info.FullMethod, ip))
		_, _, _, ok, err := r.store.Take(ctx, key)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "rate limit error: %v", err)
		}
		if !ok {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}
