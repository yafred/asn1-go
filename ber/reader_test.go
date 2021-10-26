package ber

import (
	"bytes"
	"testing"
)

func TestReadBoolean(t *testing.T) {
	in := bytes.NewReader([]byte{0xFF})

	reader := NewReader(in)

	value, err := reader.ReadBoolean()

	if err != nil {
		t.Fatal("Wrong")
	}

	if value == false {
		t.Fatal("Wrong")
	}

	_, err = reader.ReadBoolean()

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadOctetString(t *testing.T) {
	in := bytes.NewReader([]byte{0x01, 0x02})

	reader := NewReader(in)

	value, err := reader.ReadOctetString(2)

	if err != nil {
		t.Fatal("Wrong")
	}

	expectedBuffer := [2]byte{0x01, 0x02}
	if false == bytes.Equal(value, expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}

	_, err = reader.ReadOctetString(1)

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadRestrictedCharacterString(t *testing.T) {
	in := bytes.NewReader([]byte{0x61, 0x62, 0x63, 0xc3, 0xa0})

	reader := NewReader(in)

	value, err := reader.ReadRestrictedCharacterString(5)

	if err != nil {
		t.Fatal("Wrong")
	}

	expectedValue := "abcà"
	if value != expectedValue {
		t.Fatal("Wrong")
	}

	_, err = reader.ReadRestrictedCharacterString(1)

	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadLengthIndefinite(t *testing.T) {
	in := bytes.NewReader([]byte{0x80})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x0f})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x81, 0x0a})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x82, 0x01, 0xff})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x80})

	reader := NewReader(in)

	value, err := reader.ReadInteger(1)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != -128 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger1b2(t *testing.T) {
	in := bytes.NewReader([]byte{0x7f})

	reader := NewReader(in)

	value, err := reader.ReadInteger(1)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != 127 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger4b1(t *testing.T) {
	in := bytes.NewReader([]byte{0x01, 0x7d, 0x78, 0x40})

	reader := NewReader(in)

	value, err := reader.ReadInteger(4)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != 25000000 {
		t.Fatal("Wrong")
	}
}

func TestReadInteger4b2(t *testing.T) {
	in := bytes.NewReader([]byte{0xfe, 0x82, 0x87, 0xc0})

	reader := NewReader(in)

	value, err := reader.ReadInteger(4)

	if err != nil {
		t.Fatal("Wrong")
	}

	if value != -25000000 {
		t.Fatal("Wrong")
	}
}

func TestReadRelativeOID1(t *testing.T) {
	in := bytes.NewReader([]byte{0x64, 0x8f, 0x50, 0xdd, 0x60})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0xa4, 0xe5, 0xc0, 0xad, 0xa4, 0xe5, 0xc0, 0xad, 0xa4, 0xe5, 0xc0, 0xad, 0x6a})

	reader := NewReader(in)

	_, err := reader.ReadRelativeOID(18)

	// overflow
	if err == nil {
		t.Fatal("Wrong")
	}
}

func TestReadObjectIdentifier(t *testing.T) {
	in := bytes.NewReader([]byte{0x29, 0x28})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x90, 0x20, 0xdd, 0x60})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0x83, 0xa1, 0xfb, 0xf9, 0x6a})

	reader := NewReader(in)

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
	in := bytes.NewReader([]byte{0x19, 0xba, 0xef, 0x9a, 0x15, 0xa4, 0xe5, 0xc0, 0xad, 0x6a})

	reader := NewReader(in)

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

func TestReadBitString(t *testing.T) {
	in := bytes.NewReader([]byte{0x04, 0x50})

	reader := NewReader(in)

	value, err := reader.ReadBitString(2)

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if value.Get(0) {
		t.Fatal("Wrong: bit 0 should be false")
	}
	if value.Get(1) == false {
		t.Fatal("Wrong: bit 1 should be true")
	}
	if value.Get(2) {
		t.Fatal("Wrong: bit 2 should be false")
	}
	if value.Get(3) == false {
		t.Fatal("Wrong: bit 3 should be true")
	}
}

func TestReadTag(t *testing.T) {
	in := bytes.NewReader([]byte{0x1e})

	reader := NewReader(in)

	err := reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if reader.GetTagLength() != 1 {
		t.Fatal("Wrong")
	}

	if false == reader.MatchTag([]byte{0x1e}) {
		t.Fatal("Wrong")
	}
}

func TestReadTag2(t *testing.T) {
	in := bytes.NewReader([]byte{0x5f, 0x81, 0x48, 0x01, 0x19})

	reader := NewReader(in)
	var err error
	var value int

	err = reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if false == reader.MatchTag([]byte{0x5f, 0x81, 0x48}) {
		t.Fatal("Wrong")
	}

	err = reader.ReadLength()

	if err != nil {
		t.Fatal("Wrong:", err)
	}
	if reader.GetLengthValue() != 1 {
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
	in := bytes.NewReader([]byte{0x5f, 0x81, 0x48, 0x01, 0x19})

	reader := NewReader(in)

	err := reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if true == reader.MatchTag([]byte{0x5f, 0x81}) {
		t.Fatal("Wrong")
	}
}

func TestReadTagLookAhead(t *testing.T) {
	in := bytes.NewReader([]byte{0x5f, 0x64, 0x01, 0x19})

	reader := NewReader(in)

	err := reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if false == reader.LookAheadTag([][]byte{{0x5f, 0x64}}) {
		t.Fatal("Wrong")
	}
}

func TestReadTagLookAhead2(t *testing.T) {
	in := bytes.NewReader([]byte{0x5f, 0x64, 0x01, 0x19})

	reader := NewReader(in)

	err := reader.ReadTag()

	if err != nil {
		t.Fatal("Wrong:", err)
	}

	if true == reader.LookAheadTag([][]byte{{0x5f, 0x64, 0x01}}) {
		t.Fatal("Wrong")
	}
}
