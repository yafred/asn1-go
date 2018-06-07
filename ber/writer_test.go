package ber_test

import (
	"bytes"
	"testing"

	"github.com/yafred/asn1-go/ber"
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

func TestRestrictedCharacterString(t *testing.T) {
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
