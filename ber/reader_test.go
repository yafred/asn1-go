package ber_test

import (
	"bytes"
	"github.com/yafred/asn1-go/ber"
	"testing"
)

func TestReadBoolean(t *testing.T) {
	readBuffer := [1]byte{0xFF}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadBoolean()

	if err != nil {
		t.Fatal("Wrong")
	}

	if value == false {
		t.Fatal("Wrong")
	}

	value, err = reader.ReadBoolean()

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadOctetString(t *testing.T) {
	readBuffer := [...]byte{0x01, 0x02}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadOctetString(2)

	if err != nil {
		t.Fatal("Wrong")
	}

	expectedBuffer := [2]byte{0x01, 0x02}
	if false == bytes.Equal(value, expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}

	value, err = reader.ReadOctetString(1)

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadRestrictedCharacterString(t *testing.T) {
	readBuffer := [...]byte{0x61, 0x62, 0x63, 0xc3, 0xa0}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadRestrictedCharacterString(5)

	if err != nil {
		t.Fatal("Wrong")
	}

	expectedValue := "abcà"
	if value != expectedValue {
		t.Fatal("Wrong")
	}

	value, err = reader.ReadRestrictedCharacterString(1)

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadLengthIndefinite(t *testing.T) {
	readBuffer := [...]byte{0x80}

	reader := ber.NewReader(readBuffer[0:])

	err := reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong")
	}

	value := reader.GetLengthValue()

	if value != -1 {
		t.Fatal("Wrong")
	}
}

func TestReadLengthShortForm(t *testing.T) {
	readBuffer := [...]byte{0x0f}

	reader := ber.NewReader(readBuffer[0:])

	err := reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong")
	}

	value := reader.GetLengthValue()

	if value != 15 {
		t.Fatal("Wrong")
	}

	value = reader.GetLengthLength()

	if value != 1 {
		t.Fatal("Wrong")
	}
}

func TestReadLengthLongForm1(t *testing.T) {
	readBuffer := [...]byte{0x81, 0x0a}

	reader := ber.NewReader(readBuffer[0:])

	err := reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong")
	}

	value := reader.GetLengthValue()

	if value != 10 {
		t.Fatal("Wrong")
	}

	value = reader.GetLengthLength()

	if value != 2 {
		t.Fatal("Wrong")
	}
}

func TestReadLengthLongForm2(t *testing.T) {
	readBuffer := [...]byte{0x82, 0x01, 0xff}

	reader := ber.NewReader(readBuffer[0:])

	err := reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong")
	}

	value := reader.GetLengthValue()

	if value != 511 {
		t.Fatal("Wrong")
	}

	value = reader.GetLengthLength()

	if value != 3 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger1b1(t *testing.T) {
	readBuffer := [...]byte{0x80}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadInteger(1)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != -128 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger1b2(t *testing.T) {
	readBuffer := [...]byte{0x7f}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadInteger(1)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != 127 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger4b1(t *testing.T) {
	readBuffer := [...]byte{0x01, 0x7d, 0x78, 0x40}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadInteger(4)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != 25000000 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger4b2(t *testing.T) {
	readBuffer := [...]byte{0xfe, 0x82, 0x87, 0xc0}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadInteger(4)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != -25000000 {
		t.Fatal("Wrong")
	}
}

func TestReadRelativeOID1(t *testing.T) {
	readBuffer := [...]byte{0x64, 0x8f, 0x50, 0xdd, 0x60}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadRelativeOID(5)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value == nil {
		t.Fatal("Wrong")
	}

	if len(value) != 3 ||
		value[0] != 100 ||
		value[1] != 2000 ||
		value[2] != 12000 {
		t.Fatal("Wrong")
	}
}

func TestReadRelativeOID2(t *testing.T) {
	readBuffer := [...]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0xa4, 0xe5, 0xc0, 0xad, 0xa4, 0xe5, 0xc0, 0xad, 0xa4, 0xe5, 0xc0, 0xad, 0x6a}

	reader := ber.NewReader(readBuffer[0:])

	_, err := reader.ReadRelativeOID(18)

	// overflow
	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadObjectIdentifier(t *testing.T) {
	readBuffer := [...]byte{0x29, 0x28}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadObjectIdentifier(2)

	if err != nil {
		t.Fatal("Wrong")
	}

	if len(value) != 3 ||
		value[0] != 1 ||
		value[1] != 1 ||
		value[2] != 40 {
		t.Fatal("Wrong")
	}
}

func TestReadObjectIdentifier2(t *testing.T) {
	readBuffer := [...]byte{0x90, 0x20, 0xdd, 0x60}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadObjectIdentifier(4)

	if err != nil {
		t.Fatal("Wrong")
	}

	if len(value) != 3 ||
		value[0] != 2 ||
		value[1] != 2000 ||
		value[2] != 12000 {
		t.Fatal("Wrong")
	}
}

func TestReadObjectIdentifier3(t *testing.T) {
	readBuffer := [...]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0x83, 0xa1, 0xfb, 0xf9, 0x6a}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadObjectIdentifier(10)

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if len(value) != 4 ||
		value[0] != 0 ||
		value[1] != 25 ||
		value[2] != 123456789 ||
		value[3] != 876543210 {
		t.Fatal("Wrong")
	}
}

func TestReadObjectIdentifier4(t *testing.T) {
	readBuffer := [...]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0xa4, 0xe5, 0xc0, 0xad, 0x6a}

	reader := ber.NewReader(readBuffer[0:])

	value, err := reader.ReadObjectIdentifier(10)

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if len(value) != 4 ||
		value[0] != 0 ||
		value[1] != 25 ||
		value[2] != 123456789 ||
		value[3] != 9876543210 {
		t.Fatal("Wrong")
	}
}

func TestReadTag(t *testing.T) {
	readBuffer := [...]byte{0x1e}

	reader := ber.NewReader(readBuffer[0:])

	err := reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if 1 != reader.GetTagLength() {
		t.Fatal("Wrong")
	}

	if false == reader.MatchTag(readBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestReadTag2(t *testing.T) {
	readBuffer := [...]byte{0x5f, 0x81, 0x48, 0x01, 0x19}

	reader := ber.NewReader(readBuffer[0:])
	var err error
	var value int

	err = reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if false == reader.MatchTag(readBuffer[0:3]) {
		t.Fatal("Wrong")
	}

	err = reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong:", err)
	}
	if 1 != reader.GetLengthValue() {
		t.Fatal("Wrong")
	}

	value, err = reader.ReadInteger(1)

	if err != nil {
		t.Fatal("Wrong:", err)
	}
	if value != 25 {
		t.Fatal("Wrong")
	}
}

func TestReadTag3(t *testing.T) {
	readBuffer := [...]byte{0x5f, 0x81, 0x48, 0x01, 0x19}

	reader := ber.NewReader(readBuffer[0:])
	var err error

	err = reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if true == reader.MatchTag(readBuffer[0:2]) {
		t.Fatal("Wrong")
	}
}

func TestReadTagLookAhead(t *testing.T) {
	readBuffer := [...]byte{0x5f, 0x64, 0x01, 0x19}

	reader := ber.NewReader(readBuffer[0:])
	var err error

	err = reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	lookAheadBuffer := [...][]byte{readBuffer[0:2]}
	if false == reader.LookAheadTag(lookAheadBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestReadTagLookAhead2(t *testing.T) {
	readBuffer := [...]byte{0x5f, 0x64, 0x01, 0x19}

	reader := ber.NewReader(readBuffer[0:])
	var err error

	err = reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	lookAheadBuffer := [...][]byte{readBuffer[0:1]}
	if true == reader.LookAheadTag(lookAheadBuffer[0:]) {
		t.Fatal("Wrong")
	}
}
