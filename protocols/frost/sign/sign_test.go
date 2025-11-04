package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

func checkOutput(t *testing.T, rounds []round.Session, public curve.Point, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(Signature)
		assert.True(t, signature.Verify(public, m), "expected valid signature")
	}
}

func TestSign(t *testing.T) {
	group := curve.Secp256k1{}

	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := secret.ActOnBase()
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
	}

	var newPublicKey curve.Point
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: party.NewPointMap(verificationShares),
			ChainKey:           chainKey,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, err := StartSignCommon(false, false, result, partyIDs, steak)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, rounds, newPublicKey, steak)
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, public taproot.PublicKey, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, taproot.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(taproot.Signature)
		assert.True(t, public.Verify(signature, m), "expected valid signature")
	}
}

func TestSignTaproot(t *testing.T) {
	group := curve.Secp256k1{}
	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Secp256k1Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Secp256k1Scalar)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Secp256k1Point)
	}

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootConfig{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		tapRootPublicKey, err := curve.Secp256k1{}.LiftX(newPublicKey)
		genericVerificationShares := make(map[party.ID]curve.Point)
		for k, v := range result.VerificationShares {
			genericVerificationShares[k] = v
		}
		require.NoError(t, err)
		normalResult := &keygen.Config{
			ID:                 result.ID,
			Threshold:          result.Threshold,
			PrivateShare:       result.PrivateShare,
			PublicKey:          tapRootPublicKey,
			VerificationShares: party.NewPointMap(genericVerificationShares),
		}
		r, err := StartSignCommon(true, false, normalResult, partyIDs, steak)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}

func checkOutputEd25519(t *testing.T, rounds []round.Session, public []byte, m []byte) {
	for _, r := range rounds {
		if abort, ok := r.(*round.Abort); ok {
			t.Fatalf("round aborted: %v", abort.Err)
		}
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, []byte(nil), resultRound.Result, "expected ed25519 signature result")
		signature := resultRound.Result.([]byte)
		require.Len(t, signature, 64, "ed25519 signature should be 64 bytes")
		assert.True(t, ed25519.Verify(public, m, signature), "expected valid ed25519 signature")
	}
}

func TestSignEd25519(t *testing.T) {
	group := curve.Ed25519{}
	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicPoint := secret.ActOnBase()
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Ed25519Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Ed25519Scalar)
	}

	verificationShares := make(map[party.ID]*curve.Ed25519Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Ed25519Point)
	}

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Ed25519Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicPoint.(*curve.Ed25519Point),
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
			ChainKey:           chainKey,
		}
		if newPublicKey == nil {
			newPublicKey = result.PublicKey.BytesEd25519()
		}
		genericVerificationShares := make(map[party.ID]curve.Point)
		for k, v := range result.VerificationShares {
			genericVerificationShares[k] = v
		}
		normalResult := &keygen.Config{
			ID:                 result.ID,
			Threshold:          result.Threshold,
			PrivateShare:       result.PrivateShare,
			PublicKey:          result.PublicKey,
			VerificationShares: party.NewPointMap(genericVerificationShares),
		}
		r, err := StartSignCommon(false, true, normalResult, partyIDs, steak)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputEd25519(t, rounds, newPublicKey, steak)
}
