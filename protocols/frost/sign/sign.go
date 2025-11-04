package sign

import (
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

const (
	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	protocolIDEd25519 = "frost/sign-threshold-ed25519"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(taproot bool, ed25519 bool, result *keygen.Config, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        result.Threshold,
			Group:            result.PublicKey.Curve(),
		}
		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else if ed25519 {
			info.ProtocolID = protocolIDEd25519
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Helper:  helper,
			taproot: taproot,
			ed25519: ed25519,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			s_i:     result.PrivateShare,
		}, nil
	}
}
