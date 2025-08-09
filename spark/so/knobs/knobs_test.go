package knobs

import (
	"log/slog"
	"testing"

	"sync"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// newTestKnobs creates a knobs instance for testing that bypasses Kubernetes connectivity
func newTestKnobs(t *testing.T) *KnobsImpl {
	k := &KnobsImpl{
		inner:  &sync.RWMutex{},
		values: make(map[string]float64),
		logger: slog.Default().With("component", "knobs"),
	}

	return k
}

func TestKnobs(t *testing.T) {
	k := newTestKnobs(t)

	// Test GetValue with no value set
	value := k.GetValue("test_knob", 0.0)
	assert.Zero(t, value)

	// Test RolloutRandom with default value
	assert.True(t, k.RolloutRandom("test_knob", 100.0)) // 100% chance
	assert.False(t, k.RolloutRandom("test_knob", 0.0))  // 0% chance

	// Test RolloutUUID with default value
	id := uuid.New()
	assert.True(t, k.RolloutUUID("test_knob", id, 100.0)) // 100% chance
	assert.False(t, k.RolloutUUID("test_knob", id, 0.0))  // 0% chance

	// Test target-specific values
	k.inner.Lock()
	k.values["test_knob@target1"] = 50.0
	k.values["test_knob@target2"] = 0.0
	k.inner.Unlock()

	target1 := "target1"
	target2 := "target2"

	// Test GetValueTarget
	value = k.GetValueTarget("test_knob", &target1, 0.0)
	assert.InDelta(t, 50.0, value, 0.001)

	value = k.GetValueTarget("test_knob", &target2, 0.0)
	assert.InDelta(t, 0.0, value, 0.001)

	// Test RolloutRandomTarget
	assert.False(t, k.RolloutRandomTarget("test_knob", &target2, 100.0)) // 0% chance

	// Test RolloutUUIDTarget
	assert.False(t, k.RolloutUUIDTarget("test_knob", id, &target2, 1.0)) // 0% chance

	// Test RolloutUUIDTarget with 100% chance (default value)
	assert.True(t, k.RolloutUUIDTarget("non_existent_knob", id, nil, 100.0))      // 100% chance, no target
	assert.True(t, k.RolloutUUIDTarget("non_existent_knob", id, &target1, 100.0)) // 100% chance, target doesn't exist

	// Add a target with 100% chance
	k.inner.Lock()
	k.values["test_knob@target_100"] = 100.0
	k.inner.Unlock()

	target100 := "target_100"
	assert.True(t, k.RolloutUUIDTarget("test_knob", id, &target100, 0.0)) // 100% chance from target value

	// Test with different UUIDs to ensure deterministic behavior
	id2 := uuid.New()
	id3 := uuid.New()

	// These should be consistent for the same knob+UUID combination
	result1 := k.RolloutUUIDTarget("test_knob", id, &target1, 50.0)
	result2 := k.RolloutUUIDTarget("test_knob", id, &target1, 50.0)
	assert.Equal(t, result1, result2, "RolloutUUIDTarget should be deterministic for same inputs")

	// Different UUIDs with same knob should potentially give different results
	result3 := k.RolloutUUIDTarget("test_knob", id2, &target1, 50.0)
	result4 := k.RolloutUUIDTarget("test_knob", id3, &target1, 50.0)
	// Note: We can't assert they're different since it depends on the hash, but we test they're consistent
	result3Repeat := k.RolloutUUIDTarget("test_knob", id2, &target1, 50.0)
	result4Repeat := k.RolloutUUIDTarget("test_knob", id3, &target1, 50.0)
	assert.Equal(t, result3, result3Repeat, "RolloutUUIDTarget should be deterministic for id2")
	assert.Equal(t, result4, result4Repeat, "RolloutUUIDTarget should be deterministic for id3")
}

func TestKnobs_HandleConfigMap(t *testing.T) {
	k := newTestKnobs(t)

	tests := []struct {
		name           string
		configMapData  map[string]string
		expectedValues map[string]float64
	}{
		{
			name: "simple scalar values",
			configMapData: map[string]string{
				"key1":  "1",
				"key2":  "2.5",
				"scale": "100",
			},
			expectedValues: map[string]float64{
				"key1":  1.0,
				"key2":  2.5,
				"scale": 100.0,
			},
		},
		{
			name: "target-specific values using pipe syntax",
			configMapData: map[string]string{
				"spark.ssp.use_fixed_trees.enabled": "REGTEST: 100.0\nMAINNET: 50.0\n",
				"feature.rollout":                   "target1: 25.0\ntarget2: 75.0\n",
			},
			expectedValues: map[string]float64{
				"spark.ssp.use_fixed_trees.enabled@REGTEST": 100.0,
				"spark.ssp.use_fixed_trees.enabled@MAINNET": 50.0,
				"feature.rollout@target1":                   25.0,
				"feature.rollout@target2":                   75.0,
			},
		},
		{
			name: "mixed simple and target-specific values",
			configMapData: map[string]string{
				"simple_knob":    "42.0",
				"complex_knob":   "env1: 10.0\nenv2: 20.0\n",
				"another_simple": "3.14",
			},
			expectedValues: map[string]float64{
				"simple_knob":       42.0,
				"complex_knob@env1": 10.0,
				"complex_knob@env2": 20.0,
				"another_simple":    3.14,
			},
		},
		{
			name: "empty and invalid values",
			configMapData: map[string]string{
				"valid_knob":   "123.45",
				"invalid_yaml": "invalid: yaml: content",
			},
			expectedValues: map[string]float64{
				"valid_knob": 123.45,
				// invalid_yaml should not be added
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear existing values
			k.inner.Lock()
			k.values = make(map[string]float64)
			k.inner.Unlock()

			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "knobs",
					Namespace: "knobs",
				},
				Data: tt.configMapData,
			}

			k.handleConfigMap(configMap)

			// Verify expected values
			k.inner.RLock()
			actualValues := make(map[string]float64)
			for key, value := range k.values {
				actualValues[key] = value
			}
			k.inner.RUnlock()

			assert.Equal(t, tt.expectedValues, actualValues, "ConfigMap values should match expected values")
		})
	}
}

func TestKnobs_HandleConfigMap_NilData(t *testing.T) {
	k := newTestKnobs(t)

	k.inner.Lock()
	k.values["existing_knob"] = 42.0
	k.inner.Unlock()

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "knobs",
			Namespace: "knobs",
		},
		Data: nil,
	}

	k.handleConfigMap(configMap)

	k.inner.RLock()
	value, exists := k.values["existing_knob"]
	k.inner.RUnlock()

	assert.True(t, exists, "Existing knob should still exist")
	assert.InDelta(t, 42.0, value, 0.001, "Existing knob value should be unchanged")
}

func TestKnobs_RolloutUUIDConsistent(t *testing.T) {
	k := newTestKnobs(t)

	// Test specific UUIDs for deterministic rollout behavior matching Python implementation
	// Values verified with Python using knob="test" and default=50.0
	testCases := []struct {
		uuidStr  string
		expected bool
	}{
		{"25291dc3-35ad-4a88-b7d6-c010afa821f5", false}, // mod=91395, threshold=50000
		{"c0516611-6db1-4ad7-ab70-e69441308b6b", true},  // mod=3453, threshold=50000
	}

	for _, tc := range testCases {
		t.Run(tc.uuidStr, func(t *testing.T) {
			parsedUUID, err := uuid.Parse(tc.uuidStr)
			require.NoError(t, err, "Should be able to parse UUID")

			result := k.RolloutUUID("test", parsedUUID, 50.0)
			assert.Equal(t, tc.expected, result,
				"RolloutUUID should return consistent result for UUID %s with default 50%%", tc.uuidStr)

			// Test multiple times to ensure consistency - this is the key requirement
			for i := 0; i < 10; i++ {
				repeatResult := k.RolloutUUID("test", parsedUUID, 50.0)
				assert.Equal(t, tc.expected, repeatResult, "RolloutUUID should be deterministic (iteration %d)", i)
			}
		})
	}
}
