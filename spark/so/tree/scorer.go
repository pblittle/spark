package tree

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark_tree"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/treenode"
)

// PolarityScoreDepth is the depth of the tree to consider for the polarity score.
const PolarityScoreDepth = 5

// PolarityScoreAlpha is the prior probability of a user being online and swapping.
const PolarityScoreAlpha = 0.1

// PolarityScoreGamma is the exponential decay for leaves that are more distant from the candidate.
const PolarityScoreGamma = 0.5

type Scorer interface {
	Score(leafID uuid.UUID, sspPublicKey []byte, userPublicKey []byte) float32
	FetchPolarityScores(req *pb.FetchPolarityScoreRequest, stream pb.SparkTreeService_FetchPolarityScoresServer) error
}

type PolarityScorer struct {
	logger             *slog.Logger
	dbClient           *ent.Client
	probPubKeyCanClaim map[uuid.UUID]map[string]float32
}

func NewPolarityScorer(dbClient *ent.Client) *PolarityScorer {
	return &PolarityScorer{
		logger:             slog.Default(),
		dbClient:           dbClient,
		probPubKeyCanClaim: make(map[uuid.UUID]map[string]float32),
	}
}

func (s *PolarityScorer) Start(ctx context.Context) {
	const limit = 1000
	lastUpdated := time.Now().Add(-30 * 24 * time.Hour)
	for {
		s.logger.Info("checking for leaves updated after", slog.Time("last_updated", lastUpdated))
		leaves, err := s.dbClient.TreeNode.Query().
			Where(
				treenode.StatusEQ(st.TreeNodeStatusAvailable),
				treenode.UpdateTimeGTE(lastUpdated),
			).
			Order(ent.Desc(treenode.FieldUpdateTime)).
			WithParent().
			Limit(limit).
			All(ctx)
		if err != nil {
			s.logger.Error("error loading leaves", slog.Any("error", err))
		}

		s.logger.Info("found leaves to update", slog.Int("num_leaves", len(leaves)))
		for _, leaf := range leaves {
			node := leaf
			for i := 0; i < PolarityScoreDepth; i++ {
				if node.Edges.Parent == nil {
					break
				}

				parentNode, err := s.dbClient.TreeNode.Query().
					Where(treenode.ID(node.Edges.Parent.ID)).
					WithParent().
					Only(ctx)
				if err != nil {
					s.logger.Error("error loading parent", slog.Any("error", err))
					break
				}
				node = parentNode
			}
			if node != nil {
				s.UpdateLeaves(ctx, node)
			} else {
				s.logger.Error("node is nil")
			}
		}

		if len(leaves) > 0 {
			// Update lastUpdated to the most recent leaf's update time
			lastUpdated = leaves[0].UpdateTime
		}

		if len(leaves) == limit {
			time.Sleep(1 * time.Millisecond)
		} else {
			// Done for now, sleep for a while.
			time.Sleep(60 * time.Second)
		}
	}
}

// UpdateLeaves updates the polarity score for all the leaves under the given node.
func (s *PolarityScorer) UpdateLeaves(ctx context.Context, node *ent.TreeNode) {
	// Build the helper tree starting from the given node
	helperTree := buildHelperTree(ctx, node)
	leaves := helperTree.Leaves()
	s.logger.Info("helper tree", slog.Any("root", node.ID), slog.Int("leaves", len(leaves)))
	for _, leaf := range leaves {
		if _, ok := s.probPubKeyCanClaim[leaf.leafID]; !ok {
			s.probPubKeyCanClaim[leaf.leafID] = make(map[string]float32)
		}
		scores := leaf.Score()
		for owner, score := range scores {
			s.probPubKeyCanClaim[leaf.leafID][owner] = score
		}
	}
}

// buildHelperTree recursively builds the helper tree.
func buildHelperTree(ctx context.Context, n *ent.TreeNode) *HelperNode {
	helperNode := NewHelperNode(string(n.OwnerIdentityPubkey), n.ID)

	// Load and process all children
	children, err := n.QueryChildren().Where().All(ctx)
	if err != nil {
		return helperNode
	}

	for _, child := range children {
		childHelper := buildHelperTree(ctx, child)
		childHelper.parent = helperNode
		helperNode.children = append(helperNode.children, childHelper)
	}

	return helperNode
}

// Score computes a measure of how much the SSP wants the leaf vs giving it to the user.
func (s *PolarityScorer) Score(leafID uuid.UUID, sspPublicKey []byte, userPublicKey []byte) float32 {
	// Check if leaf exists in the map
	leafScores, exists := s.probPubKeyCanClaim[leafID]
	if !exists {
		return 0
	}

	// Get probabilities, defaulting to 0 if pubkey not found
	probSspCanClaim := leafScores[string(sspPublicKey)]
	probUserCanClaim := leafScores[string(userPublicKey)]

	return probSspCanClaim - probUserCanClaim
}

func (s *PolarityScorer) FetchPolarityScores(req *pb.FetchPolarityScoreRequest, stream pb.SparkTreeService_FetchPolarityScoresServer) error {
	logger := logging.GetLoggerFromContext(stream.Context()).With("method", "tree.FetchPolarityScores")

	targetPubKeys := make(map[string]bool)
	for _, pubKey := range req.PublicKeys {
		targetPubKeys[string(pubKey)] = true
	}
	if len(targetPubKeys) > 0 {
		logger.Info("fetching polarity scores", slog.Int("num_pubkeys", len(targetPubKeys)))
	} else {
		logger.Info("fetching all polarity scores")
	}

	logger.Info("loading cache", slog.Int("num_leaves", len(s.probPubKeyCanClaim)))
	for leafID, leafScores := range s.probPubKeyCanClaim {
		for pubKey, score := range leafScores {
			if len(targetPubKeys) > 0 && !targetPubKeys[pubKey] {
				continue
			}
			err := stream.Send(&pb.PolarityScore{
				LeafId:    leafID.String(),
				PublicKey: []byte(pubKey),
				Score:     score,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
