package curve

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

type Edwards struct{}

func (Edwards) NewPoint() Point {
	return &EdwardsPoint{
		value: new(edwards.PublicKey),
	}
}

func (Edwards) NewBasePoint() Point {
	curve := edwards.Edwards()
	gx := curve.Params().Gx
	gy := curve.Params().Gy

	out := &EdwardsPoint{
		value: edwards.NewPublicKey(gx, gy),
	}
	return out
}

func (Edwards) NewScalar() Scalar {
	return &EdwardsScalar{n: new(saferith.Nat)}
}

func (Edwards) ScalarBits() int {
	return 256
}

func (Edwards) SafeScalarBytes() int {
	return 32
}

// Ed25519 order: 2^252 + 27742317777372353535851937790883648493
var edwardsOrderNat, _ = new(saferith.Nat).SetHex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
var edwardsOrder = saferith.ModulusFromNat(edwardsOrderNat)

func (Edwards) Order() *saferith.Modulus {
	return edwardsOrder
}

func (Edwards) LiftX(data []byte) (*EdwardsPoint, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("EdwardsPoint.LiftX: invalid x coordinate length: %d", len(data))
	}

	// Edwards curves don't support LiftX in the same way
	return nil, errors.New("LiftX not supported for Edwards curve - use UnmarshalBinary instead")
}

func (Edwards) Name() string {
	return "edwards25519"
}

type EdwardsScalar struct {
	n *saferith.Nat
}

func edwardsEnsureInit(s *EdwardsScalar) {
	if s == nil {
		return
	}
	if s.n == nil {
		s.n = new(saferith.Nat)
	}
}

func edwardsCastScalar(generic Scalar) *EdwardsScalar {
	if generic == nil {
		return &EdwardsScalar{n: new(saferith.Nat)}
	}
	out, ok := generic.(*EdwardsScalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to EdwardsScalar: %v", generic))
	}
	if out == nil {
		return &EdwardsScalar{n: new(saferith.Nat)}
	}
	edwardsEnsureInit(out)
	return out
}

func (*EdwardsScalar) Curve() Curve {
	return Edwards{}
}

func (s *EdwardsScalar) MarshalBinary() ([]byte, error) {
	edwardsEnsureInit(s)
	// reduce and output 32 bytes
	reduced := new(saferith.Nat).Mod(s.n, edwardsOrder)
	out := reduced.Bytes()
	var fixed [32]byte
	copy(fixed[32-len(out):], out)
	return fixed[:], nil
}

func (s *EdwardsScalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for edwards scalar: %d", len(data))
	}
	edwardsEnsureInit(s)
	s.n = new(saferith.Nat).SetBytes(data)
	s.n = s.n.Mod(s.n, edwardsOrder)
	return nil
}

func (s *EdwardsScalar) Add(that Scalar) Scalar {
	edwardsEnsureInit(s)
	other := edwardsCastScalar(that)
	s.n = new(saferith.Nat).ModAdd(s.n, other.n, edwardsOrder)
	return s
}

func (s *EdwardsScalar) Sub(that Scalar) Scalar {
	edwardsEnsureInit(s)
	other := edwardsCastScalar(that)
	s.n = new(saferith.Nat).ModSub(s.n, other.n, edwardsOrder)
	return s
}

func (s *EdwardsScalar) Mul(that Scalar) Scalar {
	edwardsEnsureInit(s)
	other := edwardsCastScalar(that)
	s.n = new(saferith.Nat).Mul(s.n, other.n, -1)
	s.n = s.n.Mod(s.n, edwardsOrder)
	return s
}

func (s *EdwardsScalar) Invert() Scalar {
	edwardsEnsureInit(s)
	inverted := new(saferith.Nat).ModInverse(s.n, edwardsOrder)
	s.n = inverted
	return s
}

func (s *EdwardsScalar) Negate() Scalar {
	edwardsEnsureInit(s)
	s.n = new(saferith.Nat).ModSub(edwardsOrder.Nat(), s.n, edwardsOrder)
	return s
}

func (s *EdwardsScalar) IsOverHalfOrder() bool {
	edwardsEnsureInit(s)
	half := new(saferith.Nat).Rsh(edwardsOrder.Nat(), 1, -1)
	_, _, gt := s.n.Cmp(half)
	return gt == 1
}

func (s *EdwardsScalar) Equal(that Scalar) bool {
	edwardsEnsureInit(s)
	other := edwardsCastScalar(that)
	return s.n.Eq(other.n) == 1
}

func (s *EdwardsScalar) IsZero() bool {
	edwardsEnsureInit(s)
	return s.n.Eq(new(saferith.Nat)) == 1
}

func (s *EdwardsScalar) Set(that Scalar) Scalar {
	other := edwardsCastScalar(that)
	edwardsEnsureInit(s)
	s.n = new(saferith.Nat).SetNat(other.n)
	return s
}

func (s *EdwardsScalar) SetNat(x *saferith.Nat) Scalar {
	edwardsEnsureInit(s)
	s.n = new(saferith.Nat).Mod(x, edwardsOrder)
	return s
}

func (s *EdwardsScalar) Act(that Point) Point {
	other := edwardsCastPoint(that)
	curve := edwards.Edwards()

	// Perform scalar multiplication using big.Int from nat
	scalar := new(big.Int).SetBytes(s.n.Bytes())
	x, y := curve.ScalarMult(other.value.GetX(), other.value.GetY(), scalar.Bytes())

	out := &EdwardsPoint{
		value: edwards.NewPublicKey(x, y),
	}
	return out
}

func (s *EdwardsScalar) ActOnBase() Point {
	curve := edwards.Edwards()

	// Perform scalar base multiplication using big.Int from nat
	scalar := new(big.Int).SetBytes(s.n.Bytes())
	x, y := curve.ScalarBaseMult(scalar.Bytes())

	out := &EdwardsPoint{
		value: edwards.NewPublicKey(x, y),
	}
	return out
}

type EdwardsPoint struct {
	value *edwards.PublicKey
}

func edwardsCastPoint(generic Point) *EdwardsPoint {
	out, ok := generic.(*EdwardsPoint)
	if !ok {
		panic(fmt.Sprintf("failed to convert to EdwardsPoint: %v", generic))
	}
	return out
}

func (*EdwardsPoint) Curve() Curve {
	return Edwards{}
}

func (p *EdwardsPoint) XBytes() []byte {
	return []byte{}
}

func (p *EdwardsPoint) MarshalBinary() ([]byte, error) {
	return p.value.Serialize(), nil
}

func (p *EdwardsPoint) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for EdwardsPoint: %d", len(data))
	}

	pub, err := edwards.ParsePubKey(data)
	if err != nil {
		return fmt.Errorf("EdwardsPoint.UnmarshalBinary: %w", err)
	}
	p.value = pub
	return nil
}

func (p *EdwardsPoint) Add(that Point) Point {
	other := edwardsCastPoint(that)
	curve := edwards.Edwards()

	// Perform point addition
	x, y := curve.Add(p.value.GetX(), p.value.GetY(), other.value.GetX(), other.value.GetY())

	out := &EdwardsPoint{
		value: edwards.NewPublicKey(x, y),
	}
	return out
}

func (p *EdwardsPoint) Sub(that Point) Point {
	return p.Add(that.Negate())
}

func (p *EdwardsPoint) Set(that Point) Point {
	other := edwardsCastPoint(that)

	bytes := other.value.Serialize()
	pub, err := edwards.ParsePubKey(bytes)
	if err != nil {
		// This should not happen with a valid point.
		panic(fmt.Sprintf("failed to set EdwardsPoint: %v", err))
	}
	p.value = pub
	return p
}

func (p *EdwardsPoint) Negate() Point {
	// Negate by flipping the sign bit in the compressed representation
	serialized := p.value.Serialize()

	// For Edwards curve, negation can be done by flipping the sign bit
	var negBytes [32]byte
	copy(negBytes[:], serialized)
	negBytes[31] ^= 0x80 // Flip the sign bit

	negPub, err := edwards.ParsePubKey(negBytes[:])
	if err != nil {
		// If parsing fails, compute negation using curve operations
		curve := edwards.Edwards()
		negX := new(big.Int).Neg(p.value.GetX())
		negX.Mod(negX, curve.Params().P)
		negPub = edwards.NewPublicKey(negX, p.value.GetY())
	}

	out := &EdwardsPoint{
		value: negPub,
	}
	return out
}

func (p *EdwardsPoint) Equal(that Point) bool {
	other := edwardsCastPoint(that)
	return p.value.GetX().Cmp(other.value.GetX()) == 0 && p.value.GetY().Cmp(other.value.GetY()) == 0
}

func (p *EdwardsPoint) IsIdentity() bool {
	one := big.NewInt(1)
	zero := big.NewInt(0)
	return p.value.GetX().Cmp(zero) == 0 && p.value.GetY().Cmp(one) == 0
}

func (p *EdwardsPoint) HasEvenY() bool {
	serialized := p.value.Serialize()
	// Check if the first byte (y coordinate LSB) is even
	return (serialized[0] & 0x01) == 0
}

func (p *EdwardsPoint) XScalar() Scalar {
	// The X coordinate of an Edwards point is an element of the field F_p, but
	// a scalar is an element of F_l. These fields are different for Ed25519.
	// Returning the X coordinate as a scalar is not well-defined here.
	// Per the interface documentation, we return nil.
	return nil
}
