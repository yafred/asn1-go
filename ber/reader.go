package ber

import (
	"errors"
	"io"

	"github.com/yafred/asn1-go/types"
)

// reader helps decode ASN.1 values
type Reader struct {
	// stream to read from
	in io.Reader

	// value of last read length
	lengthLength int
	lengthValue  int

	// value of last read tag
	tagLength  int
	tagBuffer  [10]byte
	tagMatched bool
}

// NewReader creates a reader
func NewReader(in io.Reader) *Reader {
	r := new(Reader)
	r.in = in
	return r
}

// ReadOctetString decodes a []byte value from dataBuffer at current offset, raises an error if end of dataBuffer is reached
func (r *Reader) ReadOctetString(nBytes int) ([]byte, error) {
	buffer := make([]byte, nBytes)

	_, err := r.in.Read(buffer)

	return buffer[0:], err
}

// ReadRestrictedCharacterString decodes a string value from dataBuffer at current offset, raises an error if end of dataBuffer is reached
func (r *Reader) ReadRestrictedCharacterString(nBytes int) (string, error) {
	buffer := make([]byte, nBytes)

	_, err := r.in.Read(buffer)

	return string(buffer), err
}

// ReadBoolean decodes a boolean value from dataBuffer at current offset, raises an error if end of dataBuffer is reached
func (r *Reader) ReadBoolean() (bool, error) {
	aByte, err := r.readByte()
	if err != nil {
		return false, err
	}
	if aByte == 0 {
		return false, nil
	}

	return true, nil
}

// readByte reads a byte from the dataBuffer, raises an error if end of dataBuffer is reached
func (r *Reader) readByte() (byte, error) {
	buffer := make([]byte, 1)

	_, err := r.in.Read(buffer)

	return buffer[0], err
}

// ReadLength reads a length from the dataBuffer, raises an error if end of dataBuffer is reached
// raises an error if length has more than 4 bytes
func (r *Reader) ReadLength() error {
	r.lengthLength = 0
	r.lengthValue = 0

	aByte, err := r.readByte()

	if err != nil {
		return err
	}

	if aByte == 0x80 {
		r.lengthLength = 1
		r.lengthValue = -1
	} else {
		if aByte > 0x7f { // long form

			nBytes := aByte & 0x7f

			if nBytes > 4 {
				return errors.New("length value more than 4 bytes not supported")
			}

			r.lengthLength = int(nBytes) + 1
			r.lengthValue = 0

			for i := nBytes; i > 0; i-- {
				aByte, err = r.readByte()
				if err != nil {
					return err
				}
				r.lengthValue += int(aByte) << ((i - 1) * 8)
			}
		} else { // short form
			r.lengthLength = 1
			r.lengthValue = int(aByte)
		}
	}

	return nil
}

// GetLengthValue returns the last read length value (-1 if form is indefinite)
func (r *Reader) GetLengthValue() int {
	return r.lengthValue
}

// GetLengthLength returns the number of bytes used to decode last read length value
func (r *Reader) GetLengthLength() int {
	return r.lengthLength
}

// ReadInteger reads a maximum of 4 bytes from the dataBuffer to decode an int, raises an error if end of dataBuffer is reached
func (r *Reader) ReadInteger(nBytes int) (int, error) {
	if nBytes > 4 {
		return 0, errors.New("integers over 4 bytes not supported")
	}

	aByte, err := r.readByte()
	if err != nil {
		return 0, err
	}

	result := 0
	mult := 1
	if (aByte & 0x80) == 0x80 { // negative number
		mult = -1
		result = 1 // as we will shift xored bytes, there will be a difference (0xff = 0x00 ^ 0xff = -1)
	}

	if mult == -1 {
		aByte = aByte ^ 0xff
	}
	result += int(aByte) << uint((nBytes-1)*8)

	for i := nBytes - 1; i > 0; i-- {
		aByte, err = r.readByte()
		if err != nil {
			return 0, err
		}
		if mult == -1 {
			aByte = aByte ^ 0xff
		}
		shifted := int(aByte) << uint((i-1)*8)
		result += shifted
	}

	return result * mult, nil
}

// ReadBitString reads a nBytes bytes from the dataBuffer to decode a BitString, raises an error if end of dataBuffer is reached
func (r *Reader) ReadBitString(nBytes int) (types.BitString, error) {
	result := types.BitString{}

	if nBytes == 0 {
		return result, errors.New("zero length BIT STRING")
	}

	bytes := make([]byte, nBytes)
	_, err := r.in.Read(bytes)
	if err != nil {
		return result, err
	}

	paddingBits := int(bytes[0])
	if paddingBits > 7 ||
		len(bytes) == 1 && paddingBits > 0 ||
		bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
		err = errors.New("invalid padding bits in BIT STRING")
		return result, err
	}
	result.Length = (len(bytes)-1)*8 - paddingBits
	result.Bytes = bytes[1:]
	return result, nil
}

// ReadRelativeOID reads a nBytes bytes from the dataBuffer to decode a RelativeOID, raises an error if end of dataBuffer is reached
func (r *Reader) ReadRelativeOID(nBytes int) (types.RelativeOID, error) {

	if nBytes == 0 {
		err := errors.New("ReadRelativeOID need at least one byte")
		return nil, err
	}

	buffer := make([]byte, nBytes)

	_, err := r.in.Read(buffer)

	if err != nil {
		return nil, err
	}

	// The number of arcs in the RelativeOID will have the same number bytes to decode
	ret := make([]int64, nBytes)
	currentArc := -1
	var shift uint

	// for each arc, bit 8 of the last octet is zero; bit 8 of each preceding octet is one
	for i := nBytes - 1; i >= 0; i-- {
		if buffer[i]&0x80 == 0x00 {
			currentArc++
			ret[nBytes-currentArc-1] = int64(buffer[i])
			shift = 7
		} else {
			if shift > 63 {
				err := errors.New("ReadRelativeOID arc overflow")
				return nil, err
			}
			mask := int64((buffer[i] & 0x7F)) << shift
			ret[nBytes-currentArc-1] |= mask
			shift += 7
		}
	}

	return ret[nBytes-currentArc-1:], nil
}

// ReadObjectIdentifier reads a nBytes bytes from the dataBuffer to decode a ObjectIdentifier, raises an error if end of dataBuffer is reached
func (r *Reader) ReadObjectIdentifier(nBytes int) (types.ObjectIdentifier, error) {
	value, err := r.ReadRelativeOID(nBytes)
	if err != nil {
		return nil, err
	}

	ret := make([]int64, len(value)+1)
	copy(ret[1:], value)

	switch {
	case ret[1] < 40:
		ret[0] = 0
	case ret[1] < 80:
		ret[0] = 1
		ret[1] -= 40
	default:
		ret[0] = 2
		ret[1] -= 80
	}

	return ret, nil
}

// ReadTag reads a nBytes bytes from the dataBuffer to decode a tag, raises an error if end of dataBuffer is reached
func (r *Reader) ReadTag() error {
	isLastByte := false
	r.tagLength = 1
	var err error

	// read first byte
	r.tagBuffer[0], err = r.readByte()

	if err != nil {
		return err
	}

	if r.tagBuffer[0]&0x1F != 0x1F { // short form
		isLastByte = true
	}

	for i := 1; !isLastByte; i++ {
		r.tagBuffer[i], err = r.readByte()

		if err != nil {
			return err
		}

		r.tagLength++

		if r.tagBuffer[i]&0x80 == 0 {
			isLastByte = true
		}
	}

	// switch toggle (will be set again when length is read ... meaning that tag has been matched)
	r.tagMatched = false

	return nil
}

// GetTagLength returns the length of the last read tag
func (r *Reader) GetTagLength() int {
	return r.tagLength
}

// MatchTag return true if input matches last read tag
func (r *Reader) MatchTag(tag []byte) bool {
	r.tagMatched = false
	if r.tagLength == len(tag) {
		r.tagMatched = true
		for i := 0; i < r.tagLength; i++ {
			if tag[i] != r.tagBuffer[i] {
				r.tagMatched = false
				break
			}
		}
	}
	return r.tagMatched
}

// LookAheadTag return true if one item of the input matches last read tag
func (r *Reader) LookAheadTag(tags [][]byte) bool {
	foundMatch := false

	for k := 0; k < len(tags) && !foundMatch; k++ {
		tag := tags[k]
		foundMatch = false
		if r.tagLength == len(tag) {
			foundMatch = true
			for i := 0; i < len(tag); i++ {
				if tag[i] != r.tagBuffer[i] {
					foundMatch = false
					break
				}
			}
		}
	}

	return foundMatch
}
