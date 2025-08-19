package wallet

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/keys"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/objects"
)

func ExitSingleNodeTrees(
	ctx context.Context,
	config *TestWalletConfig,
	client *rpcclient.Client,
	roots []*pb.TreeNode,
	privKeys []keys.Private,
	address btcutil.Address,
	amountSats int64,
) (*wire.MsgTx, error) {
	tx, err := createTransaction(roots, address, amountSats)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	txBytes, err := common.SerializeTx(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	exitingTrees, nonces, err := createExitingTrees(roots)
	if err != nil {
		return nil, fmt.Errorf("failed to create input exiting trees: %w", err)
	}

	sparkConn, err := config.NewCoordinatorGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to coordinator: %w", err)
	}
	defer sparkConn.Close()
	sparkClient := pb.NewSparkServiceClient(sparkConn)

	prevOuts := make([]*pb.BitcoinTransactionOutput, 0)
	for _, root := range roots {
		rootTx, err := common.TxFromRawTxBytes(root.NodeTx)
		if err != nil {
			return nil, fmt.Errorf("unable to load the tx on root node %s: %w", root.Id, err)
		}
		fundingOutPoint := rootTx.TxIn[0].PreviousOutPoint
		fundingTx, err := client.GetRawTransaction(&fundingOutPoint.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch raw tx: %w", err)
		}
		fundingTxOut := fundingTx.MsgTx().TxOut[fundingOutPoint.Index]

		prevOuts = append(
			prevOuts,
			&pb.BitcoinTransactionOutput{
				Value:    fundingTxOut.Value,
				PkScript: fundingTxOut.PkScript,
			},
		)
	}
	response, err := sparkClient.ExitSingleNodeTrees(ctx, &pb.ExitSingleNodeTreesRequest{
		OwnerIdentityPublicKey: config.IdentityPublicKey().Serialize(),
		ExitingTrees:           exitingTrees,
		RawTx:                  txBytes,
		PreviousOutputs:        prevOuts,
	})
	if err != nil {
		return nil, err
	}

	treeToSigningResult := make(map[string]*pb.ExitSingleNodeTreeSigningResult)
	for _, signingResult := range response.SigningResults {
		treeToSigningResult[signingResult.TreeId] = signingResult
	}
	return userSignTransaction(config, tx, roots, privKeys, nonces, treeToSigningResult, client)
}

func ExitTrees(
	ctx context.Context,
	config *TestWalletConfig,
	client *rpcclient.Client,
	roots []*pb.TreeNode,
	privKeys []keys.Private,
	address btcutil.Address,
	amountSats int64,
) (*wire.MsgTx, error) {
	tx, err := createTransaction(roots, address, amountSats)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	txBytes, err := common.SerializeTx(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	exitingTrees, nonces, err := createExitingTrees(roots)
	if err != nil {
		return nil, fmt.Errorf("failed to create input exiting trees: %w", err)
	}

	sparkConn, err := config.NewCoordinatorGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to coordinator: %w", err)
	}
	defer sparkConn.Close()
	sspClient := pbssp.NewSparkSspInternalServiceClient(sparkConn)

	var prevOuts []*pb.BitcoinTransactionOutput
	for _, root := range roots {
		rootTx, err := common.TxFromRawTxBytes(root.NodeTx)
		if err != nil {
			return nil, fmt.Errorf("unable to load the tx on root node %s: %w", root.Id, err)
		}
		fundingOutPoint := rootTx.TxIn[0].PreviousOutPoint
		fundingTx, err := client.GetRawTransaction(&fundingOutPoint.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch raw tx: %w", err)
		}
		fundingTxOut := fundingTx.MsgTx().TxOut[fundingOutPoint.Index]

		prevOuts = append(
			prevOuts,
			&pb.BitcoinTransactionOutput{
				Value:    fundingTxOut.Value,
				PkScript: fundingTxOut.PkScript,
			},
		)
	}
	response, err := sspClient.ExitTrees(ctx, &pbssp.ExitTreesRequest{
		OwnerIdentityPublicKey: config.IdentityPublicKey().Serialize(),
		ExitingTrees:           exitingTrees,
		RawTx:                  txBytes,
		PreviousOutputs:        prevOuts,
	})
	if err != nil {
		return nil, err
	}

	treeToSigningResult := make(map[string]*pb.ExitSingleNodeTreeSigningResult)
	for _, signingResult := range response.SigningResults {
		treeToSigningResult[signingResult.TreeId] = &pb.ExitSingleNodeTreeSigningResult{
			TreeId:        signingResult.TreeId,
			SigningResult: signingResult.SigningResult,
			VerifyingKey:  signingResult.VerifyingKey,
		}
	}
	return userSignTransaction(config, tx, roots, privKeys, nonces, treeToSigningResult, client)
}

func userSignTransaction(
	config *TestWalletConfig,
	tx *wire.MsgTx,
	roots []*pb.TreeNode,
	privKeys []keys.Private,
	nonces []*objects.SigningNonce,
	treeToSigningResult map[string]*pb.ExitSingleNodeTreeSigningResult,
	client *rpcclient.Client,
) (*wire.MsgTx, error) {
	var userSigningJobs []*pbfrost.FrostSigningJob
	var txSigHashes [][]byte

	txPrevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for index, in := range tx.TxIn {
		rootTx, err := common.TxFromRawTxBytes(roots[index].NodeTx)
		if err != nil {
			return nil, err
		}
		fundingTx, err := getFundingTx(rootTx, client)
		if err != nil {
			return nil, err
		}
		txPrevOuts[in.PreviousOutPoint] = fundingTx.TxOut[0]
	}

	for index, root := range roots {
		keyPackage := CreateUserKeyPackage(privKeys[index])
		signingResult := treeToSigningResult[root.TreeId]

		nonceProto, err := nonces[index].MarshalProto()
		if err != nil {
			return nil, err
		}
		nonceCommitmentProto, err := nonces[index].SigningCommitment().MarshalProto()
		if err != nil {
			return nil, err
		}

		txSighash, err := common.SigHashFromMultiPrevOutTx(tx, index, txPrevOuts)
		if err != nil {
			return nil, err
		}
		txSigHashes = append(txSigHashes, txSighash)

		jobID := uuid.NewString()
		userSigningJobs = append(userSigningJobs, &pbfrost.FrostSigningJob{
			JobId:           jobID,
			Message:         txSighash,
			KeyPackage:      keyPackage,
			VerifyingKey:    signingResult.VerifyingKey,
			Nonce:           nonceProto,
			Commitments:     signingResult.SigningResult.SigningNonceCommitments,
			UserCommitments: nonceCommitmentProto,
		})
	}

	frostConn, err := config.NewFrostGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to frost signer: %w", err)
	}
	defer frostConn.Close()

	frostClient := pbfrost.NewFrostServiceClient(frostConn)

	userSignatures, err := frostClient.SignFrost(context.Background(), &pbfrost.SignFrostRequest{
		SigningJobs: userSigningJobs,
		Role:        pbfrost.SigningRole_USER,
	})
	if err != nil {
		return nil, err
	}

	for index, userSigningJob := range userSigningJobs {
		userNonceCommitment, err := nonces[index].SigningCommitment().MarshalProto()
		if err != nil {
			return nil, err
		}
		signingResult := treeToSigningResult[roots[index].TreeId]
		signature, err := frostClient.AggregateFrost(context.Background(), &pbfrost.AggregateFrostRequest{
			Message:            txSigHashes[index],
			SignatureShares:    signingResult.SigningResult.SignatureShares,
			PublicShares:       signingResult.SigningResult.PublicKeys,
			VerifyingKey:       signingResult.VerifyingKey,
			Commitments:        signingResult.SigningResult.SigningNonceCommitments,
			UserCommitments:    userNonceCommitment,
			UserPublicKey:      privKeys[index].Public().Serialize(),
			UserSignatureShare: userSignatures.Results[userSigningJob.JobId].SignatureShare,
		})
		if err != nil {
			return nil, err
		}
		verifyingKey, err := keys.ParsePublicKey(signingResult.VerifyingKey)
		if err != nil {
			return nil, err
		}
		err = verifySchnorrSignature(signature.Signature, txSigHashes[index], verifyingKey)
		if err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
		tx.TxIn[index].Witness = wire.TxWitness{signature.Signature}
	}
	return tx, nil
}

func verifySchnorrSignature(signature []byte, sigHash []byte, pubKey keys.Public) error {
	taprootKey := txscript.ComputeTaprootKeyNoScript(pubKey.ToBTCEC())
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if !sig.Verify(sigHash, taprootKey) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func createExitingTrees(roots []*pb.TreeNode) ([]*pb.ExitingTree, []*objects.SigningNonce, error) {
	exitingTrees := make([]*pb.ExitingTree, 0)
	nonces := make([]*objects.SigningNonce, 0)
	for index, root := range roots {
		nonce, err := objects.RandomSigningNonce()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		nonces = append(nonces, nonce)
		nonceCommitmentProto, err := nonce.SigningCommitment().MarshalProto()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal nonce commitment: %w", err)
		}
		exitingTrees = append(exitingTrees, &pb.ExitingTree{
			TreeId:                root.TreeId,
			UserSigningCommitment: nonceCommitmentProto,
			Vin:                   uint32(index),
		})
	}
	return exitingTrees, nonces, nil
}

func createTransaction(roots []*pb.TreeNode, address btcutil.Address, amountSats int64) (*wire.MsgTx, error) {
	tx := wire.NewMsgTx(3)
	for _, root := range roots {
		rootTx, err := common.TxFromRawTxBytes(root.NodeTx)
		if err != nil {
			return nil, fmt.Errorf("unable to load the tx on root node %s: %w", root.Id, err)
		}
		if len(rootTx.TxIn) != 1 {
			return nil, fmt.Errorf("expected 1 input on root node %s, got %d", root.Id, len(rootTx.TxIn))
		}
		tx.AddTxIn(wire.NewTxIn(&rootTx.TxIn[0].PreviousOutPoint, nil, nil))
	}

	pkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		return nil, fmt.Errorf("error creating output script: %w", err)
	}
	tx.AddTxOut(wire.NewTxOut(amountSats, pkScript))
	return tx, nil
}

func getFundingTx(rootTx *wire.MsgTx, client *rpcclient.Client) (*wire.MsgTx, error) {
	fundingOutPoint := rootTx.TxIn[0].PreviousOutPoint
	fundingTx, err := client.GetRawTransaction(&fundingOutPoint.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch raw tx: %w", err)
	}
	return fundingTx.MsgTx(), nil
}
