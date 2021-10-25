package ber

import (
	"github.com/yafred/asn1-go/types"
)

// writer helps encode ASN.1 values
type Writer struct {
	// size of the encoded data sitting (at the end) in the dataBuffer
	dataSize int

	dataBufferIncrement int

	// we write encoded data backwards, dataBuffer size is increased if needed
	dataBuffer []byte
}

// NewWriter creates a writer
func NewWriter(dataBufferIncrement int) *Writer {
	w := new(Writer)
	if dataBufferIncrement <= 0 {
		dataBufferIncrement = 100
	}
	w.dataBufferIncrement = dataBufferIncrement
	w.dataBuffer = make([]byte, w.dataBufferIncrement)
	return w
}

func (w *Writer) GetDataBuffer() []byte {
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	return w.dataBuffer[bufferPosition:]
}

// WriteOctetString encodes a []byte to the buffer and return length of encoded data
func (w *Writer) WriteOctetString(value []byte) int {
	w.increaseDataSize(len(value))
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	copy(w.dataBuffer[bufferPosition:], value)
	return len(value)
}

// WriteBoolean encodes a boolean to the buffer and return length of encoded data (always 1 in this case)
func (w *Writer) WriteBoolean(value bool) int {
	w.increaseDataSize(1)
	if value {
		w.dataBuffer[len(w.dataBuffer)-w.dataSize] = 0xFF
	} else {
		w.dataBuffer[len(w.dataBuffer)-w.dataSize] = 0
	}
	return 1
}

// WriteRestrictedCharacterString encodes a string as []byte to the buffer and return length of encoded data
func (w *Writer) WriteRestrictedCharacterString(value string) int {
	valueAsBytes := []byte(value)
	w.increaseDataSize(len(valueAsBytes))
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	copy(w.dataBuffer[bufferPosition:], valueAsBytes)
	return len(valueAsBytes)
}

// WriteInteger encodes an integer to the buffer and return length of encoded data
func (w *Writer) WriteInteger(value int) int {
	var nBytes int // bytes needed to write integer

	if value >= 0 {
		switch {
		case value < 0x80:
			nBytes = 1
		case value < 0x8000:
			nBytes = 2
		case value < 0x800000:
			nBytes = 3
		default:
			nBytes = 4
		}
	} else {
		switch {
		case value >= 0x80*-1:
			nBytes = 1
		case value >= 0x8000*-1:
			nBytes = 2
		case value >= 0x800000*-1:
			nBytes = 3
		default:
			nBytes = 4
		}
	}

	w.increaseDataSize(nBytes)

	beginPos := len(w.dataBuffer) - w.dataSize
	endPos := (beginPos + nBytes) - 1

	for i := endPos; i >= beginPos; i-- {
		w.dataBuffer[i] = byte(value)
		value = value >> 8
	}

	return nBytes
}

// WriteBitString encodes a BitString struct to the buffer and return length of encoded data
func (w *Writer) WriteBitString(value types.BitString) int {
	var nBytes int

	if value.Length > 0 && value.Bytes != nil && len(value.Bytes) != 0 {
		length := value.Length
		bytes := value.Bytes
		if length > 8*len(bytes) {
			length = 8 * len(bytes)
		}

		padding := length % 8
		if padding != 0 {
			padding = 8 - padding
		}

		nBytes += w.WriteOctetString(bytes)
		nBytes += w.writeByte(byte(padding))
	}
	return nBytes
}

// WriteRelativeOID encodes a RelativeOID struct to the buffer and return length of encoded data
func (w *Writer) WriteRelativeOID(value types.RelativeOID) int {
	if len(value) == 0 {
		return 0
	}

	var nBytes int

	for i := len(value) - 1; i >= 0; i-- {
		arc := value[i]
		isLast := true
		for ok := true; ok; {
			aByte := arc % 128
			arc = arc / 128
			if isLast {
				isLast = false
			} else {
				aByte |= 0x80
			}
			w.writeByte(byte(aByte))
			nBytes++
			if arc <= 0 {
				ok = false
			}
		}
	}

	return nBytes
}

// WriteObjectIdentifier encodes a ObjectIdentifier struct to the buffer and return length of encoded data
func (w *Writer) WriteObjectIdentifier(value types.ObjectIdentifier) int {

	// Error cases: just do nothing for now
	if len(value) < 2 {
		// Object Identifier must have at least 2 arcs
		return 0
	}
	if value[0] > 2 {
		// Object Identifier first arc must be 0, 1 or 2
		return 0
	}
	if value[0] == 0 && value[1] > 39 {
		// Object Identifier second arc must be < 40 when first arc is 0
		return 0
	}
	if value[0] == 1 && (value[1] == 0 || value[1] > 39) {
		// Object Identifier second arc must be > 0 and < 40 when first arc is 1
		return 0
	}

	var nBytes int

	for i := len(value) - 1; i > 1; i-- {
		arc := value[i]
		isLast := true
		for ok := true; ok; {
			aByte := arc % 128
			arc = arc / 128
			if isLast {
				isLast = false
			} else {
				aByte |= 0x80
			}
			w.writeByte(byte(aByte))
			nBytes++
			if arc <= 0 {
				ok = false
			}
		}
	}

	// then the 2 first arcs
	arc := 40*value[0] + value[1]
	isLast := true
	for ok := true; ok; {
		aByte := arc % 128
		arc = arc / 128
		if isLast {
			isLast = false
		} else {
			aByte |= 0x80
		}
		w.writeByte(byte(aByte))
		nBytes++
		if arc <= 0 {
			ok = false
		}
	}

	return nBytes
}

// WriteLength encodes a length in definite form  and return length of encoded data
func (w *Writer) WriteLength(value uint32) uint32 {
	var nBytes uint32 = 1

	switch {
	case value > 0xFFFFFF:
		nBytes = 5
	case value > 0xFFFF:
		nBytes = 4
	case value > 0xFF:
		nBytes = 3
	case value > 0x7F:
		nBytes = 2
	}

	var nShift uint
	for i := nBytes; i > 1; {
		aByte := byte(value >> nShift)
		w.writeByte(aByte)
		i = i - 1
		nShift = nShift + 8
	}

	// first byte is either number of subsequent bytes or the length itself
	firstByte := byte(value)
	if nBytes > 1 {
		firstByte = byte(nBytes-1) | 0x80
	}
	w.writeByte(firstByte)

	return nBytes
}

// WriteByte writes a byte to the buffer and return length of encoded data (always 1 in this case)
func (w *Writer) writeByte(value byte) int {
	w.increaseDataSize(1)
	w.dataBuffer[len(w.dataBuffer)-w.dataSize] = value
	return 1
}

// increaseDataSize makes sure there is enough room in the buffer
func (w *Writer) increaseDataSize(nBytes int) {
	if (w.dataSize + nBytes) > len(w.dataBuffer) {
		var increment = w.dataBufferIncrement
		if nBytes > increment {
			increment = nBytes
		}
		var oldBuffer = w.dataBuffer
		w.dataBuffer = make([]byte, w.dataSize+increment)
		var oldBufferPosition = len(oldBuffer) - w.dataSize
		var bufferPosition = len(w.dataBuffer) - w.dataSize
		copy(w.dataBuffer[bufferPosition:], oldBuffer[oldBufferPosition:])
	}
	w.dataSize += nBytes
}
