package tree

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestHelperNode(t *testing.T) {
	l1 := NewHelperNode("SSP_OWNED", uuid.New())
	l2 := NewHelperNode("USER_OWNED", uuid.New())
	l3 := NewHelperNode("SSP_OWNED", uuid.New())
	l4 := NewHelperNode("SSP_OWNED", uuid.New())

	branch1 := NewHelperNode("", uuid.New())
	branch1.AddChild(l1)
	branch1.AddChild(l2)

	branch2 := NewHelperNode("", uuid.New())
	branch2.AddChild(l3)
	branch2.AddChild(l4)

	root := NewHelperNode("test", uuid.New())
	root.AddChild(branch1)
	root.AddChild(branch2)

	scores := l1.Score()
	assert.InDelta(t, 10.4375, scores["SSP_OWNED"], 0.0001)
	assert.InDelta(t, 0.3125, scores["USER_OWNED"], 0.0001)

	scores = l2.Score()
	assert.InDelta(t, 0.4375, scores["SSP_OWNED"], 0.0001)
	assert.InDelta(t, 10.3125, scores["USER_OWNED"], 0.0001)

	scores = l3.Score()
	assert.InDelta(t, 15.1875, scores["SSP_OWNED"], 0.0001)
	assert.InDelta(t, 0.0625, scores["USER_OWNED"], 0.0001)

	scores = l4.Score()
	assert.InDelta(t, 15.1875, scores["SSP_OWNED"], 0.0001)
	assert.InDelta(t, 0.0625, scores["USER_OWNED"], 0.0001)
}

func TestNewHelperNode(t *testing.T) {
	pubKey := "test_pubkey"
	leafID := uuid.MustParse("44c1b217-cc69-4d9c-9532-8336e0791cbf")

	node := NewHelperNode(pubKey, leafID)

	assert.Equal(t, pubKey, node.pubKey)
	assert.Equal(t, leafID, node.leafID)
	assert.NotNil(t, node.parent)
	assert.Empty(t, node.children)
}

func TestAddChild(t *testing.T) {
	parent := NewHelperNode("parent", uuid.New())
	child1 := NewHelperNode("child1", uuid.New())
	child2 := NewHelperNode("child2", uuid.New())

	parent.AddChild(child1)
	parent.AddChild(child2)

	wantChildren := []*HelperNode{child1, child2}
	assert.Equal(t, wantChildren, parent.children)
	assert.Equal(t, parent, child1.parent)
	assert.Equal(t, parent, child2.parent)
}

func TestIsLeaf(t *testing.T) {
	tests := []struct {
		name  string
		setUp func() *HelperNode
		want  bool
	}{
		{
			name:  "leaf",
			setUp: func() *HelperNode { return NewHelperNode("leaf", uuid.New()) },
			want:  true,
		},
		{
			name: "non-leaf",
			setUp: func() *HelperNode {
				parent := NewHelperNode("parent", uuid.New())
				parent.AddChild(NewHelperNode("child", uuid.New()))
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
		want  map[string]int
	}{
		{
			name:  "single leaf",
			setUp: func() *HelperNode { return NewHelperNode("owner1", uuid.New()) },
			want:  map[string]int{"owner1": 1},
		},
		{
			name: "multiple leaves same owner",
			setUp: func() *HelperNode {
				parent := NewHelperNode("", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				return parent
			},
			want: map[string]int{"owner1": 3},
		},
		{
			name: "multiple leaves different owners",
			setUp: func() *HelperNode {
				parent := NewHelperNode("", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner2", uuid.New()))
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				return parent
			},
			want: map[string]int{"owner1": 2, "owner2": 1},
		},
		{
			name: "nested structure",
			setUp: func() *HelperNode {
				root := NewHelperNode("", uuid.New())

				branch1 := NewHelperNode("", uuid.New())
				branch1.AddChild(NewHelperNode("owner1", uuid.New()))
				branch1.AddChild(NewHelperNode("owner2", uuid.New()))

				branch2 := NewHelperNode("", uuid.New())
				branch2.AddChild(NewHelperNode("owner1", uuid.New()))
				branch2.AddChild(NewHelperNode("owner3", uuid.New()))

				root.AddChild(branch1)
				root.AddChild(branch2)
				return root
			},
			want: map[string]int{"owner1": 2, "owner2": 1, "owner3": 1},
		},
		{
			name: "empty pubkey leaf",
			setUp: func() *HelperNode {
				return NewHelperNode("", uuid.New())
			},
			want: map[string]int{"": 1},
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
			setup: func() *HelperNode { return NewHelperNode("owner1", uuid.New()) },
			want:  1,
		},
		{
			name: "parent with two leaves",
			setup: func() *HelperNode {
				parent := NewHelperNode("", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner2", uuid.New()))
				return parent
			},
			want: 2,
		},
		{
			name: "complex tree",
			setup: func() *HelperNode {
				root := NewHelperNode("", uuid.New())

				branch1 := NewHelperNode("", uuid.New())
				branch1.AddChild(NewHelperNode("owner1", uuid.New()))
				branch1.AddChild(NewHelperNode("owner2", uuid.New()))

				branch2 := NewHelperNode("", uuid.New())
				branch2.AddChild(NewHelperNode("owner3", uuid.New()))

				subBranch := NewHelperNode("", uuid.New())
				subBranch.AddChild(NewHelperNode("owner4", uuid.New()))
				subBranch.AddChild(NewHelperNode("owner5", uuid.New()))
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
				root := NewHelperNode("", uuid.New())

				level1 := NewHelperNode("", uuid.New())
				level2 := NewHelperNode("", uuid.New())
				level3 := NewHelperNode("", uuid.New())
				leaf := NewHelperNode("owner1", uuid.New())

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
		want  map[string]float32
	}{
		{
			name:  "single leaf",
			setup: func() *HelperNode { return NewHelperNode("owner1", uuid.New()) },
			want:  map[string]float32{"owner1": 10.0},
		},
		{
			name: "parent with mixed ownership (first child)",
			setup: func() *HelperNode {
				parent := NewHelperNode("owner0", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner2", uuid.New()))
				return parent.children[0] // Compute from the perspective of the first child
			},
			want: map[string]float32{
				"owner1": 10.25, // 10 + (1 / 2 * 0.5)
				"owner2": 0.25,  // 1 / 2 * 0.5
			},
		},
		{
			name: "parent with mixed ownership (second child)",
			setup: func() *HelperNode {
				parent := NewHelperNode("owner0", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner2", uuid.New()))
				return parent.children[1] // Compute from the perspective of the second child
			},
			want: map[string]float32{
				"owner1": 0.25,  // 1 / 2 * 0.5
				"owner2": 10.25, // 10 + (1 / 2 * 0.5)
			},
		},
		{
			name: "parent with same ownership",
			setup: func() *HelperNode {
				parent := NewHelperNode("owner0", uuid.New())
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				parent.AddChild(NewHelperNode("owner1", uuid.New()))
				return parent.children[0]
			},
			want: map[string]float32{"owner1": 15.0},
		},
		{
			name: "three level hierarchy",
			setup: func() *HelperNode {
				root := NewHelperNode("owner0", uuid.New())
				branch := NewHelperNode("owner0", uuid.New())
				leaf := NewHelperNode("owner1", uuid.New())

				root.AddChild(branch)
				branch.AddChild(leaf)
				return leaf
			},
			want: map[string]float32{"owner1": 17.5}, // 10 + 2.5 + (10 * 0.5)
		},
		{
			name: "complex mixed ownership",
			setup: func() *HelperNode {
				root := NewHelperNode("owner0", uuid.New())

				branch1 := NewHelperNode("owner0", uuid.New())
				branch1.AddChild(NewHelperNode("owner1", uuid.New()))
				branch1.AddChild(NewHelperNode("owner2", uuid.New()))

				branch2 := NewHelperNode("owner0", uuid.New())
				branch2.AddChild(NewHelperNode("owner1", uuid.New()))
				branch2.AddChild(NewHelperNode("owner3", uuid.New()))

				root.AddChild(branch1)
				root.AddChild(branch2)
				return branch1.children[0]
			},
			want: map[string]float32{"owner1": 10.375, "owner2": 0.3125, "owner3": 0.0625},
		},
		{
			name:  "empty pubkey leaf",
			setup: func() *HelperNode { return NewHelperNode("", uuid.New()) },
			want:  map[string]float32{"": 10.0},
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
