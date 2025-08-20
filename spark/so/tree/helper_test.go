package tree

import (
	"github.com/lightsparkdev/spark/common/keys"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	sspOwnedKey  = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	userOwnedKey = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	parentKey    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	testKey      = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	owner0Key    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	owner1Key    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	owner2Key    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	owner3Key    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	owner4Key    = keys.MustGeneratePrivateKeyFromRand(seeded).Public()
)

func TestHelperNode(t *testing.T) {
	l1 := NewHelperNode(sspOwnedKey, uuid.New())
	l2 := NewHelperNode(userOwnedKey, uuid.New())
	l3 := NewHelperNode(sspOwnedKey, uuid.New())
	l4 := NewHelperNode(sspOwnedKey, uuid.New())

	branch1 := NewHelperNode(parentKey, uuid.New())
	branch1.AddChild(l1)
	branch1.AddChild(l2)

	branch2 := NewHelperNode(parentKey, uuid.New())
	branch2.AddChild(l3)
	branch2.AddChild(l4)

	root := NewHelperNode(testKey, uuid.New())
	root.AddChild(branch1)
	root.AddChild(branch2)

	scores := l1.Score()
	assert.InDelta(t, 10.4375, scores[sspOwnedKey], 0.0001)
	assert.InDelta(t, 0.3125, scores[userOwnedKey], 0.0001)

	scores = l2.Score()
	assert.InDelta(t, 0.4375, scores[sspOwnedKey], 0.0001)
	assert.InDelta(t, 10.3125, scores[userOwnedKey], 0.0001)

	scores = l3.Score()
	assert.InDelta(t, 15.1875, scores[sspOwnedKey], 0.0001)
	assert.InDelta(t, 0.0625, scores[userOwnedKey], 0.0001)

	scores = l4.Score()
	assert.InDelta(t, 15.1875, scores[sspOwnedKey], 0.0001)
	assert.InDelta(t, 0.0625, scores[userOwnedKey], 0.0001)
}

func TestNewHelperNode(t *testing.T) {
	leafID := uuid.MustParse("44c1b217-cc69-4d9c-9532-8336e0791cbf")

	node := NewHelperNode(testKey, leafID)

	assert.Equal(t, testKey, node.pubKey)
	assert.Equal(t, leafID, node.leafID)
	assert.Nil(t, node.parent)
	assert.Empty(t, node.children)
}

func TestAddChild(t *testing.T) {
	child1Key := keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	child2Key := keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	parent := NewHelperNode(parentKey, uuid.New())
	child1 := NewHelperNode(child1Key, uuid.New())
	child2 := NewHelperNode(child2Key, uuid.New())

	parent.AddChild(child1)
	parent.AddChild(child2)

	wantChildren := []*HelperNode{child1, child2}
	assert.Equal(t, wantChildren, parent.children)
	assert.Equal(t, parent, child1.parent)
	assert.Equal(t, parent, child2.parent)
}

func TestIsLeaf(t *testing.T) {
	leafKey := keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	childKey := keys.MustGeneratePrivateKeyFromRand(seeded).Public()
	tests := []struct {
		name  string
		setUp func() *HelperNode
		want  bool
	}{
		{
			name:  "leaf",
			setUp: func() *HelperNode { return NewHelperNode(leafKey, uuid.New()) },
			want:  true,
		},
		{
			name: "non-leaf",
			setUp: func() *HelperNode {
				parent := NewHelperNode(parentKey, uuid.New())
				parent.AddChild(NewHelperNode(childKey, uuid.New()))
				return parent
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.setUp()
			assert.Equal(t, tt.want, node.IsLeaf())
		})
	}
}

func TestOwners(t *testing.T) {
	tests := []struct {
		name  string
		setUp func() *HelperNode
		want  map[keys.Public]int
	}{
		{
			name:  "single leaf",
			setUp: func() *HelperNode { return NewHelperNode(owner1Key, uuid.New()) },
			want:  map[keys.Public]int{owner1Key: 1},
		},
		{
			name: "multiple leaves same owner",
			setUp: func() *HelperNode {
				parent := NewHelperNode(parentKey, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				return parent
			},
			want: map[keys.Public]int{owner1Key: 3},
		},
		{
			name: "multiple leaves different owners",
			setUp: func() *HelperNode {
				parent := NewHelperNode(parentKey, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner2Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				return parent
			},
			want: map[keys.Public]int{owner1Key: 2, owner2Key: 1},
		},
		{
			name: "nested structure",
			setUp: func() *HelperNode {
				root := NewHelperNode(parentKey, uuid.New())

				branch1 := NewHelperNode(parentKey, uuid.New())
				branch1.AddChild(NewHelperNode(owner1Key, uuid.New()))
				branch1.AddChild(NewHelperNode(owner2Key, uuid.New()))

				branch2 := NewHelperNode(parentKey, uuid.New())
				branch2.AddChild(NewHelperNode(owner1Key, uuid.New()))
				branch2.AddChild(NewHelperNode(owner3Key, uuid.New()))

				root.AddChild(branch1)
				root.AddChild(branch2)
				return root
			},
			want: map[keys.Public]int{owner1Key: 2, owner2Key: 1, owner3Key: 1},
		},
		{
			name: "empty pubkey leaf",
			setUp: func() *HelperNode {
				return NewHelperNode(parentKey, uuid.New())
			},
			want: map[keys.Public]int{parentKey: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.setUp()
			assert.Equal(t, tt.want, node.Owners())
		})
	}
}

func TestLeaves(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *HelperNode
		want  int
	}{
		{
			name:  "single leaf",
			setup: func() *HelperNode { return NewHelperNode(owner1Key, uuid.New()) },
			want:  1,
		},
		{
			name: "parent with two leaves",
			setup: func() *HelperNode {
				parent := NewHelperNode(parentKey, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner2Key, uuid.New()))
				return parent
			},
			want: 2,
		},
		{
			name: "complex tree",
			setup: func() *HelperNode {
				root := NewHelperNode(parentKey, uuid.New())

				branch1 := NewHelperNode(parentKey, uuid.New())
				branch1.AddChild(NewHelperNode(owner1Key, uuid.New()))
				branch1.AddChild(NewHelperNode(owner2Key, uuid.New()))

				branch2 := NewHelperNode(parentKey, uuid.New())
				branch2.AddChild(NewHelperNode(owner3Key, uuid.New()))

				subBranch := NewHelperNode(parentKey, uuid.New())
				subBranch.AddChild(NewHelperNode(owner4Key, uuid.New()))
				subBranch.AddChild(NewHelperNode(owner0Key, uuid.New()))
				branch2.AddChild(subBranch)

				root.AddChild(branch1)
				root.AddChild(branch2)
				return root
			},
			want: 5,
		},
		{
			name: "deeply nested",
			setup: func() *HelperNode {
				root := NewHelperNode(parentKey, uuid.New())

				level1 := NewHelperNode(parentKey, uuid.New())
				level2 := NewHelperNode(parentKey, uuid.New())
				level3 := NewHelperNode(parentKey, uuid.New())
				leaf := NewHelperNode(owner1Key, uuid.New())

				root.AddChild(level1)
				level1.AddChild(level2)
				level2.AddChild(level3)
				level3.AddChild(leaf)

				return root
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.setup()
			got := node.Leaves()
			assert.Len(t, got, tt.want)
			for i, leaf := range got {
				assert.Truef(t, leaf.IsLeaf(), "Leaves()[%d] is not a leaf node", i)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *HelperNode
		want  map[keys.Public]float32
	}{
		{
			name:  "single leaf",
			setup: func() *HelperNode { return NewHelperNode(owner1Key, uuid.New()) },
			want:  map[keys.Public]float32{owner1Key: 10.0},
		},
		{
			name: "parent with mixed ownership (first child)",
			setup: func() *HelperNode {
				parent := NewHelperNode(owner0Key, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner2Key, uuid.New()))
				return parent.children[0] // Compute from the perspective of the first child
			},
			want: map[keys.Public]float32{
				owner1Key: 10.25, // 10 + (1 / 2 * 0.5)
				owner2Key: 0.25,  // 1 / 2 * 0.5
			},
		},
		{
			name: "parent with mixed ownership (second child)",
			setup: func() *HelperNode {
				parent := NewHelperNode(owner0Key, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner2Key, uuid.New()))
				return parent.children[1] // Compute from the perspective of the second child
			},
			want: map[keys.Public]float32{
				owner1Key: 0.25,  // 1 / 2 * 0.5
				owner2Key: 10.25, // 10 + (1 / 2 * 0.5)
			},
		},
		{
			name: "parent with same ownership",
			setup: func() *HelperNode {
				parent := NewHelperNode(owner0Key, uuid.New())
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				parent.AddChild(NewHelperNode(owner1Key, uuid.New()))
				return parent.children[0]
			},
			want: map[keys.Public]float32{owner1Key: 15.0},
		},
		{
			name: "three level hierarchy",
			setup: func() *HelperNode {
				root := NewHelperNode(owner0Key, uuid.New())
				branch := NewHelperNode(owner0Key, uuid.New())
				leaf := NewHelperNode(owner1Key, uuid.New())

				root.AddChild(branch)
				branch.AddChild(leaf)
				return leaf
			},
			want: map[keys.Public]float32{owner1Key: 17.5}, // 10 + 2.5 + (10 * 0.5)
		},
		{
			name: "complex mixed ownership",
			setup: func() *HelperNode {
				root := NewHelperNode(owner0Key, uuid.New())

				branch1 := NewHelperNode(owner0Key, uuid.New())
				branch1.AddChild(NewHelperNode(owner1Key, uuid.New()))
				branch1.AddChild(NewHelperNode(owner2Key, uuid.New()))

				branch2 := NewHelperNode(owner0Key, uuid.New())
				branch2.AddChild(NewHelperNode(owner1Key, uuid.New()))
				branch2.AddChild(NewHelperNode(owner3Key, uuid.New()))

				root.AddChild(branch1)
				root.AddChild(branch2)
				return branch1.children[0]
			},
			want: map[keys.Public]float32{owner1Key: 10.375, owner2Key: 0.3125, owner3Key: 0.0625},
		},
		{
			name:  "empty pubkey leaf",
			setup: func() *HelperNode { return NewHelperNode(parentKey, uuid.New()) },
			want:  map[keys.Public]float32{parentKey: 10.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.setup()
			got := node.Score()

			assert.Len(t, got, len(tt.want))

			for owner, wantScore := range tt.want {
				gotScore, exists := got[owner]
				require.Truef(t, exists, "Score() missing owner %s", owner)
				assert.InDelta(t, wantScore, gotScore, 0.001)
			}
		})
	}
}
