package knobs

import (
	"context"
	"crypto/md5"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	KnobDatabaseStatementTimeout = "spark.database.statement_timeout"
	KnobRateLimitPeriod          = "spark.so.ratelimit.period"
	KnobRateLimitLimit           = "spark.so.ratelimit.limit"
	KnobRateLimitMethods         = "spark.so.ratelimit.methods"
)

type Config struct {
	Enabled *bool `yaml:"enabled"`
}

func GetDatabaseStatementTimeoutMs(k Knobs) uint64 {
	return uint64(k.GetValue(KnobDatabaseStatementTimeout, 60) * 1000)
}

func (c *Config) IsEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// Knobs represents a collection of feature flags and their values
type Knobs interface {
	GetValue(knob string, defaultValue float64) float64
	GetValueTarget(knob string, target *string, defaultValue float64) float64
	RolloutRandomTarget(knob string, target *string, defaultValue float64) bool
	RolloutRandom(knob string, defaultValue float64) bool
	RolloutUUIDTarget(knob string, id uuid.UUID, target *string, defaultValue float64) bool
	RolloutUUID(knob string, id uuid.UUID, defaultValue float64) bool
}

type KnobsImpl struct {
	inner  *sync.RWMutex
	values map[string]float64
	logger *slog.Logger
}

// New creates a new Knobs instance, using background context to setup via
// Kubernetes.
func New(logger *slog.Logger) (*KnobsImpl, error) {
	return NewWithContext(context.Background(), logger)
}

func NewWithContext(ctx context.Context, logger *slog.Logger) (*KnobsImpl, error) {
	k := &KnobsImpl{
		inner:  &sync.RWMutex{},
		values: make(map[string]float64),
		logger: logger,
	}

	if err := k.fetchAndUpdate(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch and update knobs: %w", err)
	}

	return k, nil
}

func keyString(knob string, target *string) string {
	if target != nil {
		return fmt.Sprintf("%s@%s", knob, *target)
	}
	return knob
}

// GetValueTarget retrieves a knob value for a specific target
func (k KnobsImpl) GetValueTarget(knob string, target *string, defaultValue float64) float64 {
	k.inner.RLock()
	defer k.inner.RUnlock()

	key := keyString(knob, target)

	if value, exists := k.values[key]; exists {
		return value
	}
	return defaultValue
}

// GetValue retrieves a knob value without a target
func (k KnobsImpl) GetValue(knob string, defaultValue float64) float64 {
	return k.GetValueTarget(knob, nil, defaultValue)
}

// RolloutRandomTarget determines if a feature should be rolled out based on a random value.
// This function uses pseudo-random number generation to decide feature rollouts.
//
// Parameters:
//   - knob: The name of the feature flag/knob to check
//   - defaultValue: Default rollout percentage (0-100) to use if no specific value is configured
//   - target: Optional target identifier for environment-specific rollouts (can be nil)
//
// Returns:
//   - true if the feature should be rolled out for this request
//   - false if the feature should not be rolled out
//
// The function first checks for a target-specific value (if target is provided),
// then falls back to the defaultValue. The value is expected to be in the range 0-100
// where 0 means never roll out (0%) and 100 means always roll out (100%).
//
// Note: This function uses rand.Float64() which means results are not deterministic
// across different calls, unlike RolloutUUIDTarget which is deterministic.
func (k KnobsImpl) RolloutRandomTarget(knob string, target *string, defaultValue float64) bool {
	value := defaultValue
	if v := k.GetValueTarget(knob, target, defaultValue); v != defaultValue {
		value = v
	}
	return rand.Float64() < value/100.0
}

// RolloutRandom determines if a feature should be rolled out based on a random value without a target
func (k KnobsImpl) RolloutRandom(knob string, defaultValue float64) bool {
	return k.RolloutRandomTarget(knob, nil, defaultValue)
}

// RolloutUUIDTarget determines if a feature should be rolled out based on a UUID.
// This function uses deterministic hash-based calculation to decide feature rollouts.
//
// Parameters:
//   - knob: The name of the feature flag/knob to check
//   - id: UUID to use for deterministic rollout calculation
//   - defaultValue: Default rollout percentage (0-100) to use if no specific value is configured
//   - target: Optional target identifier for environment-specific rollouts (can be nil)
//
// Returns:
//   - true if the feature should be rolled out for this UUID
//   - false if the feature should not be rolled out
//
// The function first checks for a target-specific value (if target is provided),
// then falls back to the defaultValue. The value is expected to be in the range 0-100
// where 0 means never roll out (0%) and 100 means always roll out (100%).
//
// Algorithm:
// 1. Creates an MD5 hash of the knob name as a salt
// 2. XORs the UUID with the salt to create a deterministic value
// 3. Takes modulo 100000 of the result
// 4. Compares against threshold (value * 1000) to determine rollout
//
// Key characteristics:
//   - Deterministic: Same knob+UUID combination always returns the same result
//   - Uniform distribution: UUIDs are distributed evenly across rollout percentages
//   - Stable: Results remain consistent across application restarts
//   - Independent: Different knobs with same UUID can have different results
func (k KnobsImpl) RolloutUUIDTarget(knob string, id uuid.UUID, target *string, defaultValue float64) bool {
	value := defaultValue
	if v := k.GetValueTarget(knob, target, defaultValue); v != defaultValue {
		value = v
	}

	// Calculate salt using MD5 (128 bits)
	hash := md5.Sum([]byte(knob))
	salt := new(big.Int).SetBytes(hash[:])

	// UUID as big.Int (128 bits)
	uuidInt := new(big.Int).SetBytes(id[:])

	// XOR the UUID with the salt
	salted := new(big.Int).Xor(uuidInt, salt)

	// salted % 100000 < value * 1000
	mod := new(big.Int).Mod(salted, big.NewInt(100000))
	threshold := int64(value * 1000)
	return mod.Int64() < threshold
}

// RolloutUUID determines if a feature should be rolled out based on a UUID without a target
func (k KnobsImpl) RolloutUUID(knob string, id uuid.UUID, defaultValue float64) bool {
	return k.RolloutUUIDTarget(knob, id, nil, defaultValue)
}

// FetchAndUpdate continuously fetches and updates knob values from a Kubernetes ConfigMap.
// This function sets up a Kubernetes informer to watch for ConfigMap changes in real-time.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - error: Returns an error if Kubernetes setup fails, nil if context is cancelled
//
// Behavior:
// 1. Attempts to get Kubernetes configuration (uses in-cluster config, no kubeconfig fallback)
// 2. Creates a Kubernetes clientset for API communication
// 3. Sets up a ConfigMap informer with custom ListerWatcher to avoid LIST permission requirement
// 4. Configures event handlers for ConfigMap add/update events
// 5. Starts the informer goroutine and waits for initial cache sync
//
// ConfigMap Processing:
//   - Watches ConfigMaps in the "knobs" namespace with name "knobs"
//   - Supports both simple values (key: "100.0") and target-specific values (key: "ENV: 50.0")
//   - Automatically parses YAML format for complex configurations
//   - Updates internal knob values in real-time when ConfigMap changes
//
// Permissions Required:
//   - WATCH permission on ConfigMaps in "knobs" namespace (LIST permission not required)
func (k KnobsImpl) fetchAndUpdate(ctx context.Context) error {
	// Get Kubernetes config
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to get kubernetes config: %w", err)
		}
	}

	// Create Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Create custom ListerWatcher that only uses Watch (no List permission required)
	watchOnlyLW := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = "metadata.name=knobs"
			return clientset.CoreV1().ConfigMaps("knobs").List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = "metadata.name=knobs"
			return clientset.CoreV1().ConfigMaps("knobs").Watch(context.Background(), options)
		},
	}

	// Create ConfigMap informer
	informer := cache.NewSharedIndexInformer(
		watchOnlyLW,
		&corev1.ConfigMap{},
		0,
		cache.Indexers{},
	)

	// Add event handlers
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			k.handleConfigMap(obj.(*corev1.ConfigMap))
		},
		UpdateFunc: func(_, newObj any) {
			k.handleConfigMap(newObj.(*corev1.ConfigMap))
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add event handler: %w", err)
	}

	// Start the informer
	go informer.RunWithContext(ctx)

	// Wait for the informer to sync before returning,
	// to ensure that all feature flags are loaded before the first request.
	syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		return fmt.Errorf("failed to sync informer")
	}

	return nil
}

// handleConfigMap processes updates from the ConfigMap
func (k KnobsImpl) handleConfigMap(configMap *corev1.ConfigMap) {
	if configMap.Data == nil {
		return
	}
	k.logger.Debug("Processing ConfigMap", "configMap", configMap.Data)

	k.inner.Lock()
	defer k.inner.Unlock()

	clear(k.values)

	for name, value := range configMap.Data {
		var parsedFloat float64
		if err := yaml.Unmarshal([]byte(value), &parsedFloat); err == nil {
			k.values[name] = parsedFloat
			continue
		}

		var parsedMap map[string]float64
		if err := yaml.Unmarshal([]byte(value), &parsedMap); err == nil {
			for target, targetValue := range parsedMap {
				key := fmt.Sprintf("%s@%s", name, target)
				k.values[key] = targetValue
			}
			continue
		}

		k.logger.Warn("Unknown knob value type", "name", name, "value", value)
	}
	k.logger.Info("Updated knobs", "knobs", k.values)
}

type fixedKnobs struct {
	values map[string]float64
}

// NewFixedKnobs creates a new Knobs instance that simply maps fixed strings to
// values.  This is useful for testing and development purposes and almost
// certainly should not be used in production.
func NewFixedKnobs(values map[string]float64) Knobs {
	return &fixedKnobs{values: values}
}

func (m fixedKnobs) GetValueTarget(knob string, target *string, defaultValue float64) float64 {
	key := knob
	if target != nil {
		key = fmt.Sprintf("%s@%s", knob, *target)
	}

	if value, exists := m.values[key]; exists {
		return value
	}
	return defaultValue
}

func (m fixedKnobs) GetValue(knob string, defaultValue float64) float64 {
	return m.GetValueTarget(knob, nil, defaultValue)
}

func (m fixedKnobs) RolloutRandomTarget(knob string, target *string, defaultValue float64) bool {
	value := m.GetValueTarget(knob, target, defaultValue)
	return value > 0
}

func (m fixedKnobs) RolloutRandom(knob string, defaultValue float64) bool {
	return m.RolloutRandomTarget(knob, nil, defaultValue)
}

func (m fixedKnobs) RolloutUUIDTarget(knob string, id uuid.UUID, target *string, defaultValue float64) bool {
	value := m.GetValueTarget(knob, target, defaultValue)
	return value > 0
}

func (m fixedKnobs) RolloutUUID(knob string, id uuid.UUID, defaultValue float64) bool {
	return m.RolloutUUIDTarget(knob, id, nil, defaultValue)
}
