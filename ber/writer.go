package ber

// Writer helps encode ASN.1 values
type writer struct {
	// size of the encoded data sitting (at the end) in the dataBuffer
	dataSize int

	dataBufferIncrement int

	// we write encoded data backwards, dataBuffer size is increased if needed
	dataBuffer []byte
}

// NewWriter creates a writer
func NewWriter(dataBufferIncrement int) *writer {
	w := new(writer)
	if dataBufferIncrement <= 0 {
		dataBufferIncrement = 100
	}
	w.dataBufferIncrement = dataBufferIncrement
	w.dataBuffer = make([]byte, w.dataBufferIncrement)
	return w
}

func (w *writer) GetDataBuffer() []byte {
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	return w.dataBuffer[bufferPosition:]
}

// WriteOctetString writes a []byte to the buffer and return length of encoded data
func (w *writer) WriteOctetString(value []byte) int {
	w.increaseDataSize(len(value))
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	copy(w.dataBuffer[bufferPosition:], value)
	return len(value)
}

// WriteBoolean writes a boolean to the buffer and return length of encoded data (always 1 in this case)
func (w *writer) WriteBoolean(value bool) int {
	w.increaseDataSize(1)
	if value == true {
		w.dataBuffer[len(w.dataBuffer)-w.dataSize] = 0xFF
	} else {
		w.dataBuffer[len(w.dataBuffer)-w.dataSize] = 0
	}
	return 1
}

// WriteRestrictedCharacterString writes a string as []byte to the buffer and return length of encoded data
func (w *writer) WriteRestrictedCharacterString(value string) int {
	valueAsBytes := []byte(value)
	w.increaseDataSize(len(valueAsBytes))
	var bufferPosition = len(w.dataBuffer) - w.dataSize
	copy(w.dataBuffer[bufferPosition:], valueAsBytes)
	return len(valueAsBytes)
}

// WriteByte writes a byte to the buffer and return length of encoded data (always 1 in this case)
func (w *writer) writeByte(value byte) int {
	w.increaseDataSize(1)
	w.dataBuffer[len(w.dataBuffer)-w.dataSize] = value
	return 1
}

// increaseDataSize makes sure there is enough room in the buffer
func (w *writer) increaseDataSize(nBytes int) {
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
