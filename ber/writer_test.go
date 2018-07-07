package ber_test

import (
	"bytes"
	"github.com/yafred/asn1-go/asn1"
	"github.com/yafred/asn1-go/ber"
	"testing"
)

func TestWriteBoolean(t *testing.T) {
	writer := ber.NewWriter(10)

	encoded := writer.WriteBoolean(true)

	if encoded != 1 {
		t.Fatal("Should be 1")
	}

	expectedBuffer := [1]byte{0xFF}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteOctetString(t *testing.T) {
	writer := ber.NewWriter(10)
	value := [...]byte{0x01, 0x02, 0x03}

	encoded := writer.WriteOctetString(value[0:])

	if encoded != len(value) {
		t.Fatal("Should be ", len(value))
	}
	if false == bytes.Equal(writer.GetDataBuffer(), value[0:]) {
		t.Fatal("Wrong")
	}
}

func TestBufferIncrement(t *testing.T) {
	writer := ber.NewWriter(3)

	value1 := [...]byte{0x01, 0x02}
	var encoded = writer.WriteOctetString(value1[0:])
	if encoded != len(value1) {
		t.Fatal("Should be ", len(value1))
	}

	value2 := [...]byte{0x03, 0x04}
	encoded = writer.WriteOctetString(value2[0:])
	if encoded != len(value2) {
		t.Fatal("Should be ", len(value2))
	}

	value3 := [...]byte{0x0a, 0x0b, 0x0c, 0x0d}
	encoded = writer.WriteOctetString(value3[0:])
	if encoded != len(value3) {
		t.Fatal("Should be ", len(value3))
	}

	expectedBuffer := [...]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x03, 0x04, 0x01, 0x02}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteRestrictedCharacterString(t *testing.T) {
	writer := ber.NewWriter(10)

	value := "Hello"
	var encoded = writer.WriteRestrictedCharacterString(value)
	if encoded != len(value) {
		t.Fatal("Should be ", len(value))
	}
	expectedBuffer := [...]byte{72, 101, 108, 108, 111}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteLengthShort(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteLength(100)
	if encoded != 1 {
		t.Fatal("Should be 1")
	}
	expectedBuffer := [...]byte{0x64}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteLength1b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteLength(201)
	if encoded != 2 {
		t.Fatal("Should be 2")
	}
	expectedBuffer := [...]byte{0x81, 0xc9}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteLength2b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteLength(500)
	if encoded != 3 {
		t.Fatal("Should be 3")
	}
	expectedBuffer := [...]byte{0x82, 0x01, 0xf4}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteLength3b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteLength(500000)
	if encoded != 4 {
		t.Fatal("Should be 4")
	}
	expectedBuffer := [...]byte{0x83, 0x07, 0xa1, 0x20}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteLength4b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteLength(80000000)
	if encoded != 5 {
		t.Fatal("Should be 5")
	}
	expectedBuffer := [...]byte{0x84, 0x04, 0xc4, 0xb4, 0x00}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger1b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(127)
	if encoded != 1 {
		t.Fatal("Should be 1")
	}
	expectedBuffer := [...]byte{0x7f}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger1b2(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(-128)
	if encoded != 1 {
		t.Fatal("Should be 1")
	}
	expectedBuffer := [...]byte{0x80}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger2b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(500)
	if encoded != 2 {
		t.Fatal("Should be 2")
	}
	expectedBuffer := [...]byte{0x01, 0xf4}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger3b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(500000)
	if encoded != 3 {
		t.Fatal("Should be 3")
	}
	expectedBuffer := [...]byte{0x07, 0xa1, 0x20}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger4b(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(80000000)
	if encoded != 4 {
		t.Fatal("Should be 4")
	}
	expectedBuffer := [...]byte{0x04, 0xc4, 0xb4, 0x00}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteInteger4b2(t *testing.T) {
	writer := ber.NewWriter(10)

	var encoded = writer.WriteInteger(-25000000)
	if encoded != 4 {
		t.Fatal("Should be 4")
	}
	expectedBuffer := [...]byte{0xfe, 0x82, 0x87, 0xc0}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteBitString(t *testing.T) {
	writer := ber.NewWriter(10)

	bStringBytes := [...]byte{0x00, 0x20, 0x08}
	bString := asn1.BitString{
		Bytes: bStringBytes[0:], Length: 21,
	}

	var encoded = writer.WriteBitString(bString)
	if encoded != 4 {
		t.Fatal("Should be 4")
	}
	expectedBuffer := [...]byte{0x03, 0x00, 0x20, 0x08}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteBitString2(t *testing.T) {
	writer := ber.NewWriter(10)

	var bString asn1.BitString
	bString.Set(20, true)
	bString.Set(10, true)

	var encoded = writer.WriteBitString(bString)
	if encoded != 4 {
		t.Fatal("Should be 4")
	}
	expectedBuffer := [...]byte{0x03, 0x00, 0x20, 0x08}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}
func TestWriteRelativeOID(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.RelativeOID([]int64{100, 2000, 12000})

	var encoded = writer.WriteRelativeOID(value)

	if encoded != 5 {
		t.Fatal("Should be 5")
	}

	expectedBuffer := [...]byte{0x64, 0x8f, 0x50, 0xdd, 0x60}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier1(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 0 {
		t.Fatal("Should be 0")
	}

	expectedBuffer := [...]byte{}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier2(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{1})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 0 {
		t.Fatal("Should be 0")
	}

	expectedBuffer := [...]byte{}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier3(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{3, 40})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 0 {
		t.Fatal("Should be 0")
	}

	expectedBuffer := [...]byte{}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier4(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{1, 40})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 0 {
		t.Fatal("Should be 0")
	}

	expectedBuffer := [...]byte{}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier5(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{1, 1, 40})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 2 {
		t.Fatal("Should be 2")
	}

	expectedBuffer := [...]byte{0x29, 0x28}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier6(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{1, 1, 200})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 3 {
		t.Fatal("Should be 3")
	}

	expectedBuffer := [...]byte{0x29, 0x81, 0x48}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}

func TestWriteObjectIdentifier7(t *testing.T) {

	writer := ber.NewWriter(10)

	value := asn1.ObjectIdentifier([]int64{2, 2000, 12000})

	var encoded = writer.WriteObjectIdentifier(value)

	if encoded != 4 {
		t.Fatal("Should be 4")
	}

	expectedBuffer := [...]byte{0x90, 0x20, 0xdd, 0x60}
	if false == bytes.Equal(writer.GetDataBuffer(), expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}
}
