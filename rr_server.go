package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	rrMagic0 byte = 'R'
	rrMagic1 byte = 'R'

	rrVersion1 byte = 1
	rrVersion2 byte = 2

	rrFlagOpen  byte = 1 << 0
	rrFlagClose byte = 1 << 1
)

type rrRequest struct {
	Flags byte
	SID   [16]byte
	CSeq  uint32
	CAck  uint32
	CPoll uint32 // 0 => old ordered path; >0 => v2 downlink poll id
	Data  []byte
}

type rrResponse struct {
	Flags byte
	SAck  uint32
	SSeq  uint32
	Data  []byte
}

func decodeRRRequest(b []byte) (rrRequest, error) {
	var req rrRequest

	if len(b) < 30 {
		return req, fmt.Errorf("rr request too short: %d", len(b))
	}
	if b[0] != rrMagic0 || b[1] != rrMagic1 {
		return req, errors.New("rr bad magic")
	}

	switch b[2] {
	case rrVersion1:
		req.Flags = b[3]
		copy(req.SID[:], b[4:20])
		req.CSeq = binary.BigEndian.Uint32(b[20:24])
		req.CAck = binary.BigEndian.Uint32(b[24:28])
		req.CPoll = 0

		dataLen := int(binary.BigEndian.Uint16(b[28:30]))
		if len(b) != 30+dataLen {
			return req, fmt.Errorf("rr bad request length: have=%d want=%d", len(b), 30+dataLen)
		}
		if dataLen > 0 {
			req.Data = append([]byte(nil), b[30:]...)
		}
		return req, nil

	case rrVersion2:
		if len(b) < 34 {
			return req, fmt.Errorf("rr v2 request too short: %d", len(b))
		}

		req.Flags = b[3]
		copy(req.SID[:], b[4:20])
		req.CSeq = binary.BigEndian.Uint32(b[20:24])
		req.CAck = binary.BigEndian.Uint32(b[24:28])
		req.CPoll = binary.BigEndian.Uint32(b[28:32])

		dataLen := int(binary.BigEndian.Uint16(b[32:34]))
		if len(b) != 34+dataLen {
			return req, fmt.Errorf("rr v2 bad request length: have=%d want=%d", len(b), 34+dataLen)
		}
		if dataLen > 0 {
			req.Data = append([]byte(nil), b[34:]...)
		}
		return req, nil

	default:
		return req, fmt.Errorf("rr bad version: %d", b[2])
	}
}

func encodeRRResponse(resp rrResponse) []byte {
	out := make([]byte, 14+len(resp.Data))
	out[0] = rrMagic0
	out[1] = rrMagic1
	out[2] = rrVersion1 // keep response wire unchanged for commit 1
	out[3] = resp.Flags
	binary.BigEndian.PutUint32(out[4:8], resp.SAck)
	binary.BigEndian.PutUint32(out[8:12], resp.SSeq)
	binary.BigEndian.PutUint16(out[12:14], uint16(len(resp.Data)))
	copy(out[14:], resp.Data)
	return out
}

func rrSIDString(sid [16]byte) string {
	return hex.EncodeToString(sid[:])
}

const rrDLWindow = 2

type rrPollCacheEntry struct {
	resp rrResponse
	at   time.Time
}

type rrSession struct {
	mu sync.Mutex

	sid [16]byte
	tcp net.Conn

	lastSeen time.Time

	lastCSeq uint32
	nextSSeq uint32

	// legacy v1 stop-and-wait downlink path
	pendingSeq  uint32
	pendingData []byte

	// v2 downlink window path
	pendingDL map[uint32][]byte           // SSeq -> payload, not cumulatively acked yet
	pollCache map[uint32]rrPollCacheEntry // CPoll -> exact cached response
	lastCPoll uint32

	clientClosed bool
	serverClosed bool
}

type rrSessionStore struct {
	mu sync.Mutex

	sessions  map[[16]byte]*rrSession
	upstream  string
	ioTimeout time.Duration
	rrChunk   int
}

func newRRSessionStore(upstream string, ioTimeout time.Duration, rrChunk int) *rrSessionStore {
	return &rrSessionStore{
		sessions:  make(map[[16]byte]*rrSession),
		upstream:  upstream,
		ioTimeout: ioTimeout,
		rrChunk:   rrChunk,
	}
}

func (s *rrSessionStore) get(sid [16]byte) *rrSession {
	s.mu.Lock()
	sess := s.sessions[sid]
	s.mu.Unlock()
	return sess
}

func (s *rrSessionStore) getOrCreate(sid [16]byte) (*rrSession, bool, error) {
	s.mu.Lock()
	existing := s.sessions[sid]
	s.mu.Unlock()
	if existing != nil {
		return existing, false, nil
	}

	tcp, err := net.DialTimeout("tcp", s.upstream, 5*time.Second)
	if err != nil {
		return nil, false, err
	}

	sess := &rrSession{
		sid:       sid,
		tcp:       tcp,
		lastSeen:  time.Now(),
		pendingDL: make(map[uint32][]byte, rrDLWindow),
		pollCache: make(map[uint32]rrPollCacheEntry, rrDLWindow*4),
	}

	s.mu.Lock()
	existing = s.sessions[sid]
	if existing != nil {
		s.mu.Unlock()
		_ = tcp.Close()
		return existing, false, nil
	}
	s.sessions[sid] = sess
	s.mu.Unlock()

	return sess, true, nil
}

func (s *rrSessionStore) remove(sid [16]byte) {
	s.mu.Lock()
	sess := s.sessions[sid]
	delete(s.sessions, sid)
	s.mu.Unlock()

	if sess != nil {
		_ = sess.tcp.Close()
	}
}

func rrCloneResponse(resp rrResponse) rrResponse {
	out := resp
	if len(resp.Data) > 0 {
		out.Data = append([]byte(nil), resp.Data...)
	}
	return out
}

func rrAckLegacyPendingLocked(sess *rrSession, cack uint32) {
	if sess.pendingSeq != 0 && cack >= sess.pendingSeq {
		sess.pendingSeq = 0
		sess.pendingData = nil
	}
}

func rrAckWindowLocked(sess *rrSession, cack uint32) {
	if cack == 0 {
		return
	}
	for sseq := range sess.pendingDL {
		if sseq <= cack {
			delete(sess.pendingDL, sseq)
		}
	}
}

func rrTrimPollCacheLocked(sess *rrSession, cack uint32, cpoll uint32) {
	if cpoll > sess.lastCPoll {
		sess.lastCPoll = cpoll
	}

	for id, ent := range sess.pollCache {
		// If its payload is already cumulatively acked, this cache entry is no longer useful.
		if ent.resp.SSeq != 0 && ent.resp.SSeq <= cack {
			delete(sess.pollCache, id)
			continue
		}

		// Bound cache growth even for empty-poll responses.
		if id+8 < sess.lastCPoll {
			delete(sess.pollCache, id)
		}
	}
}

func rrAssignedSSeqLocked(sess *rrSession, sseq uint32) bool {
	for _, ent := range sess.pollCache {
		if ent.resp.SSeq == sseq {
			return true
		}
	}
	return false
}

func rrPickUnassignedDLLocked(sess *rrSession, cack uint32) (uint32, []byte, bool) {
	var best uint32
	var payload []byte

	for sseq, data := range sess.pendingDL {
		if sseq <= cack {
			continue
		}
		if rrAssignedSSeqLocked(sess, sseq) {
			continue
		}
		if best == 0 || sseq < best {
			best = sseq
			payload = data
		}
	}

	if best == 0 {
		return 0, nil, false
	}
	return best, payload, true
}

func rrFillOneDLLocked(sess *rrSession, store *rrSessionStore, rrHold time.Duration, sidText, reqID string) {
	if sess.serverClosed {
		return
	}
	if len(sess.pendingDL) >= rrDLWindow {
		return
	}

	buf := make([]byte, store.rrChunk)

	deadline := time.Now()
	if rrHold > 0 {
		deadline = deadline.Add(rrHold)
	}
	_ = sess.tcp.SetReadDeadline(deadline)

	n, readErr := sess.tcp.Read(buf)
	_ = sess.tcp.SetReadDeadline(time.Time{})

	if n > 0 {
		sess.nextSSeq++
		sess.pendingDL[sess.nextSSeq] = append([]byte(nil), buf[:n]...)
	}

	if readErr != nil {
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			return
		}
		sess.serverClosed = true
		if !errors.Is(readErr, io.EOF) {
			log.Printf("reqid=%s rr sid=%s upstream read err=%v", reqID, sidText, readErr)
		}
	}
}

func rrBuildPollRespLocked(sess *rrSession, req rrRequest, store *rrSessionStore, rrHold time.Duration, sidText, reqID string) rrResponse {
	if ent, ok := sess.pollCache[req.CPoll]; ok {
		return rrCloneResponse(ent.resp)
	}

	// Refresh window/cache against latest cumulative ack and newest poll id.
	rrAckWindowLocked(sess, req.CAck)
	rrTrimPollCacheLocked(sess, req.CAck, req.CPoll)

	resp := rrResponse{
		SAck: sess.lastCSeq,
	}

	if sseq, data, ok := rrPickUnassignedDLLocked(sess, req.CAck); ok {
		resp.SSeq = sseq
		resp.Data = append([]byte(nil), data...)
	} else if !sess.serverClosed {
		rrFillOneDLLocked(sess, store, rrHold, sidText, reqID)

		if sseq, data, ok := rrPickUnassignedDLLocked(sess, req.CAck); ok {
			resp.SSeq = sseq
			resp.Data = append([]byte(nil), data...)
		}
	}

	if sess.serverClosed {
		resp.Flags |= rrFlagClose
	}

	sess.pollCache[req.CPoll] = rrPollCacheEntry{
		resp: rrCloneResponse(resp),
		at:   time.Now(),
	}

	return resp
}

func handleRRHTTP(w http.ResponseWriter, r *http.Request, reqID string, store *rrSessionStore, rrHold time.Duration) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if store == nil {
		http.Error(w, "rr store is nil", http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(store.rrChunk+64)))
	if err != nil {
		http.Error(w, "rr bad request body", http.StatusBadRequest)
		return
	}

	req, err := decodeRRRequest(body)
	if err != nil {
		http.Error(w, "rr bad request", http.StatusBadRequest)
		return
	}
	if len(req.Data) > store.rrChunk {
		http.Error(w, "rr request payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	sidText := rrSIDString(req.SID)

	var sess *rrSession
	var created bool

	if req.Flags&rrFlagOpen != 0 {
		sess, created, err = store.getOrCreate(req.SID)
		if err != nil {
			log.Printf("reqid=%s rr sid=%s dial upstream FAIL %s err=%v", reqID, sidText, store.upstream, err)
			http.Error(w, "rr upstream dial failed", http.StatusBadGateway)
			return
		}
		if created {
			log.Printf("reqid=%s rr sid=%s open upstream=%s remote=%s", reqID, sidText, store.upstream, r.RemoteAddr)
		}
	} else {
		sess = store.get(req.SID)
		if sess == nil {
			http.Error(w, "rr session not found", http.StatusGone)
			return
		}
	}

	var resp rrResponse
	var removeSession bool
	var fatalErr error
	var fatalStatus int

	sess.mu.Lock()
	sess.lastSeen = time.Now()

	rrAckLegacyPendingLocked(sess, req.CAck)

	if req.CPoll != 0 {
		rrAckWindowLocked(sess, req.CAck)
		rrTrimPollCacheLocked(sess, req.CAck, req.CPoll)
	}

	if len(req.Data) > 0 {
		switch {
		case req.CSeq == sess.lastCSeq+1:
			if store.ioTimeout > 0 {
				_ = sess.tcp.SetWriteDeadline(time.Now().Add(store.ioTimeout))
			}
			if err = writeFull(sess.tcp, req.Data); err != nil {
				fatalErr = fmt.Errorf("rr upstream write failed sid=%s: %w", sidText, err)
				fatalStatus = http.StatusBadGateway
				removeSession = true
			} else {
				sess.lastCSeq = req.CSeq
			}
		case req.CSeq <= sess.lastCSeq:
		default:
			fatalErr = fmt.Errorf("rr out of order sid=%s cseq=%d last=%d", sidText, req.CSeq, sess.lastCSeq)
			fatalStatus = http.StatusConflict
		}
	}

	if fatalErr == nil && req.Flags&rrFlagClose != 0 && !sess.clientClosed {
		sess.clientClosed = true
		if tc, ok := sess.tcp.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	if fatalErr == nil {
		if req.CPoll != 0 {
			resp = rrBuildPollRespLocked(sess, req, store, rrHold, sidText, reqID)
		} else {
			resp.SAck = sess.lastCSeq

			if sess.pendingSeq != 0 {
				resp.SSeq = sess.pendingSeq
				resp.Data = append([]byte(nil), sess.pendingData...)
			} else if !sess.serverClosed {
				buf := make([]byte, store.rrChunk)

				deadline := time.Now()
				if rrHold > 0 {
					deadline = deadline.Add(rrHold)
				}
				_ = sess.tcp.SetReadDeadline(deadline)

				n, readErr := sess.tcp.Read(buf)
				_ = sess.tcp.SetReadDeadline(time.Time{})

				if n > 0 {
					sess.nextSSeq++
					sess.pendingSeq = sess.nextSSeq
					sess.pendingData = append([]byte(nil), buf[:n]...)
					resp.SSeq = sess.pendingSeq
					resp.Data = append([]byte(nil), sess.pendingData...)
				}

				if readErr != nil {
					if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					} else {
						sess.serverClosed = true
						if !errors.Is(readErr, io.EOF) {
							log.Printf("reqid=%s rr sid=%s upstream read err=%v", reqID, sidText, readErr)
						}
					}
				}
			}

			if sess.serverClosed {
				resp.Flags |= rrFlagClose
			}
		}
	}

	sess.mu.Unlock()

	if fatalErr != nil {
		if removeSession {
			store.remove(req.SID)
		}
		http.Error(w, fatalErr.Error(), fatalStatus)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = w.Write(encodeRRResponse(resp))
}
