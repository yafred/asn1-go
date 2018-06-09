package asn1

// ObjectIdentifier is the Go implementation of ASN.1 OBJECT IDENTIFIER.
type ObjectIdentifier []int64

// RelativeOID is the Go implementation of ASN.1 RELATIVE-OID.
type RelativeOID []int64

// BitString is the Go implementation of  ASN.1 BIT STRING
type BitString struct {
	Bytes  []byte // bytes holding the BIT STRING. First bit is bit 8 of byte 0
	Length int    // length of the BIT STRING in bits.
}

// Get retreives the bool value of a single bit
func (b *BitString) Get(i int) bool {
	if i < 0 || i >= b.Length {
		return false
	}
	x := i / 8
	y := 7 - uint(i%8)
	bitValue := int(b.Bytes[x]>>y) & 1
	return bitValue == 1
}

// Set sets the bool value of a single bit
func (b *BitString) Set(i int, value bool) {
	if i < 0 {
		return
	}
	// make sure Bytes is big enough
	if len(b.Bytes) < i/8+1 {
		extraBytes := i/8 + 1 - len(b.Bytes)
		var newBuffer = make([]byte, len(b.Bytes)+extraBytes)
		copy(newBuffer, b.Bytes[0:])
		b.Bytes = newBuffer
	}

	x := i / 8
	y := uint(i % 8)
	mask := 0x80 >> y
	if value == true {
		b.Bytes[x] = byte(int(b.Bytes[x]) | mask)
	} else {
		mask = mask ^ 0xff
		b.Bytes[x] = byte(int(b.Bytes[x]) & mask)
	}

	if i+1 > b.Length {
		b.Length = i + 1
	}

}
