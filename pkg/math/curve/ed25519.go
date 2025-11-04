package curve

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"
)

// Ed25519 implements the Curve interface for Ed25519 using Ristretto encoding.
type Ed25519 struct{}

var ed25519BaseX, ed25519BaseY field.Element

func init() {
	// Base point coordinates for Ed25519 (Ristretto generator)
	// This is the canonical generator point G
	Gx, _ := new(field.Element).SetBytes([]byte{
		0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
		0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
		0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
		0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
	})
	Gy, _ := new(field.Element).SetBytes([]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	})
	ed25519BaseX.Set(Gx)
	ed25519BaseY.Set(Gy)
}

// Ristretto constants
var (
	d, _ = new(field.Element).SetBytes([]byte{
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	})
	sqrtM1, _ = new(field.Element).SetBytes([]byte{
		0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
		0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
		0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
		0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
	})
	sqrtADMinusOne, _ = new(field.Element).SetBytes([]byte{
		0x1b, 0x2e, 0x7b, 0x49, 0xa0, 0xf6, 0x97, 0x7e,
		0xbd, 0x54, 0x78, 0x1b, 0x0c, 0x8e, 0x9d, 0xaf,
		0xfd, 0xd1, 0xf5, 0x31, 0xc9, 0xfc, 0x3c, 0x0f,
		0xac, 0x48, 0x83, 0x2b, 0xbf, 0x31, 0x69, 0x37,
	})
	invSqrtAMinusD, _ = new(field.Element).SetBytes([]byte{
		0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
		0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
		0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
		0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
	})
	oneMinusDSQ, _ = new(field.Element).SetBytes([]byte{
		0x76, 0xc1, 0x5f, 0x94, 0xc1, 0x09, 0x7c, 0xe2,
		0x0f, 0x35, 0x5e, 0xcd, 0x38, 0xa1, 0x81, 0x2c,
		0xe4, 0xdf, 0x70, 0xbe, 0xdd, 0xab, 0x94, 0x99,
		0xd7, 0xe0, 0xb3, 0xb2, 0xa8, 0x72, 0x90, 0x02,
	})
	dMinusOneSQ, _ = new(field.Element).SetBytes([]byte{
		0x20, 0x4d, 0xed, 0x44, 0xaa, 0x5a, 0xad, 0x31,
		0x99, 0x19, 0x1e, 0xb0, 0x2c, 0x4a, 0x9e, 0xd2,
		0xeb, 0x4e, 0x9b, 0x52, 0x2f, 0xd3, 0xdc, 0x4c,
		0x41, 0x22, 0x6c, 0xf6, 0x7a, 0xb3, 0x68, 0x59,
	})
	zero = new(field.Element)
	one  = new(field.Element).One()
	two  = new(field.Element).Add(one, one)
	_    = new(field.Element).Subtract(zero, one)
)

var ed25519OrderNat, _ = new(saferith.Nat).SetHex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")
var ed25519Order = saferith.ModulusFromNat(ed25519OrderNat)

func (Ed25519) NewPoint() Point {
	p := new(Ed25519Point)
	p.point.Set(edwards25519.NewIdentityPoint())
	return p
}

func (Ed25519) NewBasePoint() Point {
	p := edwards25519.NewGeneratorPoint()
	return &Ed25519Point{point: *p}
}

func (Ed25519) NewScalar() Scalar {
	return new(Ed25519Scalar)
}

func (Ed25519) ScalarBits() int {
	return 252
}

func (Ed25519) SafeScalarBytes() int {
	return 64
}

func (Ed25519) Order() *saferith.Modulus {
	return ed25519Order
}

func (Ed25519) Name() string {
	return "ed25519"
}

// BytesEd25519 returns the canonical byte representation of the underlying
// edwards25519.Point, normalized with regard to the cofactor.
func (p *Ed25519Point) BytesEd25519() []byte {
	// Remove cofactor: [8^{-1}][8]P
	var pCopy edwards25519.Point
	pCopy.Set(&p.point)
	pCopy.MultByCofactor(&pCopy)
	// 8^{-1} mod q in bytes
	eightInv, _ := edwards25519.NewScalar().SetCanonicalBytes([]byte{
		121, 47, 220, 226, 41, 229, 6, 97,
		208, 218, 28, 125, 179, 157, 211, 7,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 6,
	})
	var result edwards25519.Point
	result.ScalarMult(eightInv, &pCopy)
	return result.Bytes()
}

type Ed25519Scalar struct {
	value edwards25519.Scalar
}

func ed25519CastScalar(generic Scalar) *Ed25519Scalar {
	out, ok := generic.(*Ed25519Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ed25519Scalar: %v", generic))
	}
	return out
}

func (*Ed25519Scalar) Curve() Curve {
	return Ed25519{}
}

func (s *Ed25519Scalar) MarshalBinary() ([]byte, error) {
	return s.value.Bytes(), nil
}

func (s *Ed25519Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ed25519 scalar: %d", len(data))
	}
	var exactData [32]byte
	copy(exactData[:], data)
	if _, err := s.value.SetCanonicalBytes(exactData[:]); err != nil {
		return errors.New("invalid bytes for ed25519 scalar")
	}
	return nil
}

func (s *Ed25519Scalar) Add(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	var result edwards25519.Scalar
	result.Add(&s.value, &other.value)
	s.value = result
	return s
}

func (s *Ed25519Scalar) Sub(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	var result edwards25519.Scalar
	result.Subtract(&s.value, &other.value)
	s.value = result
	return s
}

func (s *Ed25519Scalar) Mul(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	var result edwards25519.Scalar
	result.Multiply(&s.value, &other.value)
	s.value = result
	return s
}

func (s *Ed25519Scalar) Invert() Scalar {
	var result edwards25519.Scalar
	result.Invert(&s.value)
	s.value = result
	return s
}

func (s *Ed25519Scalar) Negate() Scalar {
	var result edwards25519.Scalar
	result.Negate(&s.value)
	s.value = result
	return s
}

func (s *Ed25519Scalar) IsOverHalfOrder() bool {
	// Check if scalar is greater than half the order
	// Order is 2^252 + 27742317777372353535851937790883648493
	// Half order is approximately 0xf6ffff...ff3f
	halfOrderBytes := []byte{
		0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	}
	var halfOrder edwards25519.Scalar
	halfOrder.SetCanonicalBytes(halfOrderBytes)
	if s.value.Equal(&halfOrder) == 1 {
		return true
	}
	// Compare bytes lexicographically from high to low
	sBytes := s.value.Bytes()
	for i := len(sBytes) - 1; i >= 0; i-- {
		if sBytes[i] > halfOrderBytes[i] {
			return true
		}
		if sBytes[i] < halfOrderBytes[i] {
			return false
		}
	}
	return false // equal, which we already checked
}

func (s *Ed25519Scalar) Equal(that Scalar) bool {
	other := ed25519CastScalar(that)
	return s.value.Equal(&other.value) == 1
}

func (s *Ed25519Scalar) IsZero() bool {
	var zero edwards25519.Scalar
	return s.value.Equal(&zero) == 1
}

func (s *Ed25519Scalar) Set(that Scalar) Scalar {
	other := ed25519CastScalar(that)
	s.value.Set(&other.value)
	return s
}

func (s *Ed25519Scalar) SetNat(x *saferith.Nat) Scalar {
	reduced := new(saferith.Nat).Mod(x, ed25519Order)
	bytes := reduced.Bytes()
	if len(bytes) > 32 {
		bytes = bytes[:32]
	}
	var exactData [32]byte
	copy(exactData[32-len(bytes):], bytes)
	_, err := s.value.SetCanonicalBytes(exactData[:])
	if err != nil {
		// If SetCanonicalBytes fails, try SetUniformBytes as fallback
		// This handles cases where the bytes might not be in canonical form
		uniformBytes := make([]byte, 64)
		copy(uniformBytes[:32], exactData[:])
		_, _ = s.value.SetUniformBytes(uniformBytes)
	}
	return s
}

// SetUniformBytes sets the scalar from 64 uniformly distributed bytes.
// This matches the behavior of frost-ed25519's SetUniformBytes for challenge computation.
func (s *Ed25519Scalar) SetUniformBytes(b []byte) error {
	if len(b) != 64 {
		return fmt.Errorf("SetUniformBytes requires exactly 64 bytes, got %d", len(b))
	}
	_, err := s.value.SetUniformBytes(b)
	return err
}

func (s *Ed25519Scalar) Act(that Point) Point {
	other := ed25519CastPoint(that)
	out := &Ed25519Point{}
	var result edwards25519.Point
	result.ScalarMult(&s.value, &other.point)
	out.point = result
	return out
}

func (s *Ed25519Scalar) ActOnBase() Point {
	out := &Ed25519Point{}
	var result edwards25519.Point
	result.ScalarBaseMult(&s.value)
	out.point = result
	return out
}

type Ed25519Point struct {
	point edwards25519.Point
}

func ed25519CastPoint(generic Point) *Ed25519Point {
	out, ok := generic.(*Ed25519Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ed25519Point: %v", generic))
	}
	return out
}

func (*Ed25519Point) Curve() Curve {
	return Ed25519{}
}

func (p *Ed25519Point) MarshalBinary() ([]byte, error) {
	return p.bytes(), nil
}

func (p *Ed25519Point) bytes() []byte {
	X, Y, Z, T := p.point.ExtendedCoordinates()
	tmp := &field.Element{}

	// Ristretto encoding
	u1 := &field.Element{}
	u1.Add(Z, Y).Multiply(u1, tmp.Subtract(Z, Y))

	u2 := &field.Element{}
	u2.Multiply(X, Y)

	invSqrt := &field.Element{}
	invSqrt.SqrtRatio(one, tmp.Square(u2).Multiply(tmp, u1))

	den1, den2 := &field.Element{}, &field.Element{}
	den1.Multiply(invSqrt, u1)
	den2.Multiply(invSqrt, u2)
	zInv := &field.Element{}
	zInv.Multiply(den1, den2).Multiply(zInv, T)

	ix0, iy0 := &field.Element{}, &field.Element{}
	ix0.Multiply(X, sqrtM1)
	iy0.Multiply(Y, sqrtM1)
	enchantedDenominator := &field.Element{}
	enchantedDenominator.Multiply(den1, invSqrtAMinusD)

	rotate := tmp.Multiply(T, zInv).IsNegative()

	x, y := &field.Element{}, &field.Element{}
	x.Select(iy0, X, rotate)
	y.Select(ix0, Y, rotate)
	z := Z
	denInv := &field.Element{}
	denInv.Select(enchantedDenominator, den2, rotate)

	isNegative := tmp.Multiply(x, zInv).IsNegative()
	y.Select(tmp.Negate(y), y, isNegative)

	s := tmp.Subtract(z, y).Multiply(tmp, denInv).Absolute(tmp)

	b := make([]byte, 32)
	copy(b, s.Bytes())
	return b
}

func (p *Ed25519Point) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ed25519Point: %d", len(data))
	}

	s := &field.Element{}
	s.SetBytes(data)

	if !bytes.Equal(s.Bytes(), data) {
		return errInvalidEncoding
	}

	if s.IsNegative() == 1 {
		return errInvalidEncoding
	}

	sSqr := &field.Element{}
	sSqr.Square(s)

	u1 := &field.Element{}
	u1.Subtract(one, sSqr)

	u2 := &field.Element{}
	u2.Add(one, sSqr)

	u2Sqr := &field.Element{}
	u2Sqr.Square(u2)

	v := &field.Element{}
	v.Square(u1).Multiply(v, d).Negate(v).Subtract(v, u2Sqr)

	invSqrt, tmp := &field.Element{}, &field.Element{}
	_, wasSquare := invSqrt.SqrtRatio(one, tmp.Multiply(v, u2Sqr))

	denX, denY := &field.Element{}, &field.Element{}
	denX.Multiply(invSqrt, u2)
	denY.Multiply(invSqrt, denX).Multiply(denY, v)

	var X, Y, Z, T field.Element
	X.Multiply(two, s).Multiply(&X, denX).Absolute(&X)
	Y.Multiply(u1, denY)
	Z.One()
	T.Multiply(&X, &Y)

	if wasSquare == 0 || T.IsNegative() == 1 || Y.Equal(zero) == 1 {
		return errInvalidEncoding
	}

	if _, err := p.point.SetExtendedCoordinates(&X, &Y, &Z, &T); err != nil {
		return errInvalidEncoding
	}
	return nil
}

var errInvalidEncoding = errors.New("ed25519: invalid element encoding")

func (p *Ed25519Point) Add(that Point) Point {
	other := ed25519CastPoint(that)
	out := &Ed25519Point{}
	var result edwards25519.Point
	result.Add(&p.point, &other.point)
	out.point = result
	return out
}

func (p *Ed25519Point) Sub(that Point) Point {
	return p.Add(that.Negate())
}

func (p *Ed25519Point) Set(that Point) Point {
	other := ed25519CastPoint(that)
	p.point.Set(&other.point)
	return p
}

func (p *Ed25519Point) Negate() Point {
	out := &Ed25519Point{}
	var result edwards25519.Point
	result.Negate(&p.point)
	out.point = result
	return out
}

func (p *Ed25519Point) Equal(that Point) bool {
	other := ed25519CastPoint(that)
	X1, Y1, _, _ := p.point.ExtendedCoordinates()
	X2, Y2, _, _ := other.point.ExtendedCoordinates()

	var f0, f1 field.Element
	f0.Multiply(X1, Y2)
	f1.Multiply(Y1, X2)
	out := f0.Equal(&f1)

	f0.Multiply(Y1, Y2)
	f1.Multiply(X1, X2)
	out = out | f0.Equal(&f1)

	return out == 1
}

func (p *Ed25519Point) IsIdentity() bool {
	var identity edwards25519.Point
	identity.Set(edwards25519.NewIdentityPoint())
	return p.point.Equal(&identity) == 1
}

func (p *Ed25519Point) XScalar() Scalar {
	// Not typically used for Ed25519, but required by interface
	X, _, _, _ := p.point.ExtendedCoordinates()
	bytes := X.Bytes()
	var exactData [32]byte
	copy(exactData[:], bytes)
	scalar := &Ed25519Scalar{}
	scalar.value.SetCanonicalBytes(exactData[:])
	return scalar
}

// Implement encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
var _ encoding.BinaryMarshaler = (*Ed25519Point)(nil)
var _ encoding.BinaryUnmarshaler = (*Ed25519Point)(nil)
var _ encoding.BinaryMarshaler = (*Ed25519Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Ed25519Scalar)(nil)
