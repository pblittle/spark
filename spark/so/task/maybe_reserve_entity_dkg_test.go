//go:build postgres
// +build postgres

package task_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	epg "github.com/fergusstrange/embedded-postgres"
	_ "github.com/lib/pq"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/task"
	testutil "github.com/lightsparkdev/spark/test_util"
)

// newPgTestClient opens an ent Client on the given DSN and ensures the schema exists.
func newPgTestClient(t *testing.T, dsn string) *ent.Client {
	client, err := ent.Open("postgres", dsn)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, client.Schema.Create(ctx))

	return client
}

// spinUpPostgres starts an ephemeral postgres and returns a DSN and a stop func.
func spinUpPostgres(t *testing.T) (dsn string, stop func()) {
	// pick a free TCP port for each test
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	// give each test its own runtime dir so parallel runs don’t clash
	tmpDir := t.TempDir()

	cfg := epg.DefaultConfig().
		Username("postgres").
		Password("postgres").
		Database("spark_test").
		RuntimePath(tmpDir). // binaries & data
		Port(uint32(port))

	pg := epg.NewDatabase(cfg)
	require.NoError(t, pg.Start())
	stop = func() { _ = pg.Stop() }

	dsn = cfg.GetConnectionURL() + "?sslmode=disable"
	return
}

// getReserveEntityDkgTask returns the startup task we are testing.
func getReserveEntityDkgTask() (task.StartupTask, error) {
	for _, t := range task.AllStartupTasks() {
		if t.Name == "maybe_reserve_entity_dkg" {
			return t, nil
		}
	}
	return task.StartupTask{}, assert.AnError
}

// pruneOperators keeps only the current operator in the SigningOperatorMap so
// that ExecuteTaskWithAllOperators() becomes a cheap no-op in unit tests.
func pruneOperators(cfg *so.Config) {
	for id := range cfg.SigningOperatorMap {
		if id != cfg.Identifier {
			delete(cfg.SigningOperatorMap, id)
		}
	}
}

// mockSparkInternalServiceServer provides a mock implementation of the gRPC service
// for testing cross-operator communication.
type mockSparkInternalServiceServer struct {
	spark_internal.UnimplementedSparkInternalServiceServer
	errToReturn        error
	expectedKeyshareID string
}

func (s *mockSparkInternalServiceServer) ReserveEntityDkgKey(ctx context.Context, req *spark_internal.ReserveEntityDkgKeyRequest) (*emptypb.Empty, error) {
	if s.errToReturn != nil {
		return nil, s.errToReturn
	}
	if s.expectedKeyshareID != "" && s.expectedKeyshareID != req.KeyshareId {
		return nil, status.Errorf(codes.InvalidArgument, "expected keyshare %s, got %s", s.expectedKeyshareID, req.KeyshareId)
	}
	return &emptypb.Empty{}, nil
}

func TestReserveEntityDkg_OperatorDown(t *testing.T) {
	tests := []struct {
		name            string
		failOneOperator bool
	}{
		{
			name:            "all operators succeed",
			failOneOperator: false,
		},
		{
			name:            "one operator fails",
			failOneOperator: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dsn, stop := spinUpPostgres(t)
			defer stop()

			client := newPgTestClient(t, dsn)
			defer client.Close()

			ctx := context.Background()
			ctx, sessionCtx, err := db.NewTestContext(t, ctx, "postgres", dsn)
			require.NoError(t, err)
			require.NoError(t, sessionCtx.Client.Schema.Create(ctx))
			defer sessionCtx.Close()

			cfg, err := testutil.TestConfig()
			require.NoError(t, err)
			cfg.Index = 0 // coordinator

			var failingOperatorID string
			for id := range cfg.SigningOperatorMap {
				if id != cfg.Identifier {
					failingOperatorID = id
					break
				}
			}

			servers := []*grpc.Server{}
			for id, operator := range cfg.SigningOperatorMap {
				if id == cfg.Identifier {
					continue
				}
				lis, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				operator.AddressRpc = lis.Addr().String()

				var injectedErr error
				if tc.failOneOperator && id == failingOperatorID {
					injectedErr = status.Error(codes.Unavailable, "I am down for maintenance")
				}

				s := grpc.NewServer()
				spark_internal.RegisterSparkInternalServiceServer(s, &mockSparkInternalServiceServer{errToReturn: injectedErr})
				servers = append(servers, s)
				go func() { _ = s.Serve(lis) }()
			}
			t.Cleanup(func() {
				for _, s := range servers {
					s.Stop()
				}
			})

			// Seed keyshare.
			sk := client.SigningKeyshare.Create().
				SetStatus(st.KeyshareStatusAvailable).
				SetSecretShare([]byte("secret")).
				SetPublicKey([]byte("pubkey")).
				SetPublicShares(map[string][]byte{}).
				SetMinSigners(2).
				SetCoordinatorIndex(0).
				SaveX(ctx)

			reserveTask, err := getReserveEntityDkgTask()
			require.NoError(t, err)
			err = reserveTask.RunOnce(cfg, client, nil)

			if tc.failOneOperator {
				require.Error(t, err)
				require.Contains(t, err.Error(), "Unavailable")

				// EntityDkgKey should still exist due to earlier commit.
				edkg, qerr := client.EntityDkgKey.Query().WithSigningKeyshare().Only(ctx)
				require.NoError(t, qerr)
				require.NotNil(t, edkg.Edges.SigningKeyshare)
				assert.Equal(t, sk.ID, edkg.Edges.SigningKeyshare.ID)
			} else {
				require.NoError(t, err)
				edkg, qerr := client.EntityDkgKey.Query().WithSigningKeyshare().Only(ctx)
				require.NoError(t, qerr)
				require.NotNil(t, edkg.Edges.SigningKeyshare)
				assert.Equal(t, sk.ID, edkg.Edges.SigningKeyshare.ID)
			}
		})
	}
}

// TestReserveEntityDkg_Idempotent ensures running the task twice is safe.
func TestReserveEntityDkg_Idempotent(t *testing.T) {
	dsn, stop := spinUpPostgres(t)
	defer stop()

	client := newPgTestClient(t, dsn)
	defer client.Close()

	ctx := context.Background()
	ctx, sessionCtx, err := db.NewTestContext(t, ctx, "postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, sessionCtx.Client.Schema.Create(ctx))
	defer sessionCtx.Close()

	cfg, err := testutil.TestConfig()
	require.NoError(t, err)
	cfg.Index = 0
	pruneOperators(cfg)

	// Pre-create an EntityDkgKey and mark keyshare in use
	sk := client.SigningKeyshare.Create().
		SetStatus(st.KeyshareStatusAvailable).
		SetSecretShare([]byte("secret")).
		SetPublicKey([]byte("pubkey")).
		SetPublicShares(map[string][]byte{}).
		SetMinSigners(2).
		SetCoordinatorIndex(0).
		SaveX(ctx)

	reserveTask, err := getReserveEntityDkgTask()
	require.NoError(t, err)
	err = reserveTask.RunOnce(cfg, client, nil)
	require.NoError(t, err)

	// Run again to ensure idempotency.
	err = reserveTask.RunOnce(cfg, client, nil)
	require.NoError(t, err)

	count, err := client.EntityDkgKey.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "should still have exactly one EntityDkgKey")

	edkg, qerr := client.EntityDkgKey.Query().WithSigningKeyshare().Only(ctx)
	require.NoError(t, qerr)
	require.NotNil(t, edkg.Edges.SigningKeyshare)
	assert.Equal(t, sk.ID, edkg.Edges.SigningKeyshare.ID)
}

// TestReserveEntityDkg_NonCoordinator verifies that non-coordinator operators
// do not attempt to reserve an entity DKG key.
func TestReserveEntityDkg_NonCoordinator(t *testing.T) {
	dsn, stop := spinUpPostgres(t)
	defer stop()

	client := newPgTestClient(t, dsn)
	defer client.Close()

	ctx := context.Background()
	ctx, sessionCtx, err := db.NewTestContext(t, ctx, "postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, sessionCtx.Client.Schema.Create(ctx))
	defer sessionCtx.Close()

	cfg, err := testutil.TestConfig()
	require.NoError(t, err)
	cfg.Index = 1 // non-coordinator
	pruneOperators(cfg)

	reserveTask, err := getReserveEntityDkgTask()
	require.NoError(t, err)
	err = reserveTask.RunOnce(cfg, client, nil)
	require.NoError(t, err)

	count, err := client.EntityDkgKey.Query().Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "non-coordinators should not create an EntityDkgKey")
}
