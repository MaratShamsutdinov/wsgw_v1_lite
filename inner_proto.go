package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// Inner protocol: multiple logical records packed into one WS Binary frame.
// Format: [type:1][len:varint u32][payload:len]
//
// Types:
//
//	0x01 DATA  - payload: raw TCP bytes
//	0x02 PAD   - payload: random bytes (ignored)
//	0x03 PING  - payload: optional (ignored)
//	0x04 CLOSE - payload: optional; treated as EOF
const (
	innerDATA  byte = 0x01
	innerPAD   byte = 0x02
	innerPING  byte = 0x03
	innerCLOSE byte = 0x04
)

var ioErrShort = errors.New("inner: short buffer")

// appendInner appends one record to dst and returns updated slice.
func appendInner(dst []byte, typ byte, payload []byte) []byte {
	// worst-case varint for u32 is 5 bytes
	need := 1 + 5 + len(payload)
	if cap(dst)-len(dst) < need {
		nd := make([]byte, len(dst), len(dst)+need+256)
		copy(nd, dst)
		dst = nd
	}
	dst = append(dst, typ)
	var tmp [5]byte
	n := binary.PutUvarint(tmp[:], uint64(len(payload)))
	dst = append(dst, tmp[:n]...)
	dst = append(dst, payload...)
	return dst
}

// parseOneInner parses one record from b.
// Returns: typ, payloadSlice (view into b), bytesConsumed, error.
func parseOneInner(b []byte) (byte, []byte, int, error) {
	if len(b) < 2 {
		return 0, nil, 0, ioErrShort
	}
	typ := b[0]
	ln, n := binary.Uvarint(b[1:])
	if n <= 0 {
		return 0, nil, 0, errors.New("inner: bad varint")
	}
	if ln > uint64(^uint32(0)) {
		return 0, nil, 0, errors.New("inner: len too big")
	}
	need := 1 + n + int(ln)
	if len(b) < need {
		return 0, nil, 0, ioErrShort
	}
	p := b[1+n : need]
	return typ, p, need, nil
}

// appendPad appends PAD record with random bytes length 0..padMax.
// If padMax<=0 => no-op.
func appendPad(dst []byte, pad []byte, padN int) []byte {
	if padN <= 0 {
		return dst
	}
	return appendInner(dst, innerPAD, pad[:padN])
}

// -----------------------------------------------------------------------------
// Len+Pad внутри innerDATA payload:
//
// [2 bytes realLen big-endian][real data bytes][zero padding ...]
//
// packLenPad — помогает на клиенте: формирует payload для innerDATA.
// unpackLenPad — помогает на сервере: достаёт "real" bytes (без паддинга).
// -----------------------------------------------------------------------------

var errLenPadShort = errors.New("lenpad: short")
var errLenPadBad = errors.New("lenpad: bad realLen")

// packLenPad builds: [u16 realLen BE][data][zero padding] up to minPayload bytes total.
// minPayload includes the 2-byte header.
// If minPayload <= 0 => no extra padding (only header+data).
func packLenPad(data []byte, minPayload int) []byte {
	realLen := len(data)
	if realLen > 0xFFFF {
		realLen = 0xFFFF
		data = data[:realLen]
	}

	total := 2 + realLen
	if minPayload > total {
		total = minPayload
	}

	out := make([]byte, total) // zeroed => padding is zeros
	binary.BigEndian.PutUint16(out[0:2], uint16(realLen))
	copy(out[2:2+realLen], data)
	return out
}

// unpackLenPad returns only the real data portion, never padding.
// Errors:
//   - errLenPadShort if len(p)<2
//   - errLenPadBad   if realLen > len(p)-2
func unpackLenPad(p []byte) ([]byte, error) {
	if len(p) < 2 {
		// можно и io.ErrUnexpectedEOF, но отдельная ошибка удобнее в логах
		_ = io.ErrUnexpectedEOF
		return nil, errLenPadShort
	}
	realLen := int(binary.BigEndian.Uint16(p[0:2]))
	if realLen > len(p)-2 {
		return nil, errLenPadBad
	}
	if realLen == 0 {
		return []byte{}, nil
	}
	return p[2 : 2+realLen], nil
}
