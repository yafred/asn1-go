package asn1_test

import (
	"bytes"
	"github.com/yafred/asn1-go/asn1"
	"testing"
)

func TestBitString1(t *testing.T) {
	var value asn1.BitString

	value.Set(0, true)

	if value.Length != 1 {
		t.Fatal("Should be 1")
	}

	expectedBuffer := [1]byte{0x80}
	if false == bytes.Equal(value.Bytes, expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}

	check := value.Get(0)
	if check == false {
		t.Fatal("Wrong")
	}
}

func TestBitString2(t *testing.T) {
	initialBytes := [1]byte{0xff}
	value := asn1.BitString{Bytes: initialBytes[0:], Length: 8}

	value.Set(0, false)

	if value.Length != 8 {
		t.Fatal("Should be 8")
	}

	expectedBuffer := [1]byte{0x7f}
	if false == bytes.Equal(value.Bytes, expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}

}

func TestBitString3(t *testing.T) {
	var value asn1.BitString

	value.Set(20, true)
	value.Set(10, true)

	if value.Length != 21 {
		t.Fatal("Should be 21")
	}

	expectedBuffer := [3]byte{0x00, 0x20, 0x08}
	if false == bytes.Equal(value.Bytes, expectedBuffer[0:]) {
		t.Fatal("Wrong")
	}

	check := value.Get(10)
	if check == false {
		t.Fatal("Wrong")
	}
}
