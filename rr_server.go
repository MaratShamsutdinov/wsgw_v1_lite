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

	rrVersion byte = 1

	rrFlagOpen  byte = 1 << 0
	rrFlagClose byte = 1 << 1
)

type rrRequest struct {
	Flags byte
	SID   [16]byte
	CSeq  uint32
	CAck  uint32
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
	if b[2] != rrVersion {
		return req, fmt.Errorf("rr bad version: %d", b[2])
	}

	req.Flags = b[3]
	copy(req.SID[:], b[4:20])
	req.CSeq = binary.BigEndian.Uint32(b[20:24])
	req.CAck = binary.BigEndian.Uint32(b[24:28])

	dataLen := int(binary.BigEndian.Uint16(b[28:30]))
	if len(b) != 30+dataLen {
		return req, fmt.Errorf("rr bad request length: have=%d want=%d", len(b), 30+dataLen)
	}
	if dataLen > 0 {
		req.Data = append([]byte(nil), b[30:]...)
	}

	return req, nil
}

func encodeRRResponse(resp rrResponse) []byte {
	out := make([]byte, 14+len(resp.Data))
	out[0] = rrMagic0
	out[1] = rrMagic1
	out[2] = rrVersion
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

const rrServerLogMode = "baseline"

type rrServerSessionStats struct {
	StartedAt   time.Time
	Requests    int64
	UpBytes     int64
	DownBytes   int64
	WriteErrs   int64
	ReadErrs    int64
	RemoteClose int64
	ClientClose int64
	CloseSent   int64
	Non200      int64
	OutOfOrder  int64
	LastErr     string
}

func rrHumanBytes(n int64) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(1024))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func rrServerLogSummaryLocked(sidText string, sess *rrSession) {
	if sess.summaryLogged {
		return
	}
	sess.summaryLogged = true

	log.Printf(
		"rr sid=%s summary mode=%s dur=%s reqs=%d up=%s down=%s closeSent=%d clientClose=%d remoteClose=%d gone=%d outOfOrder=%d writeErrs=%d readErrs=%d non200=%d err=%q",
		sidText,
		rrServerLogMode,
		time.Since(sess.stats.StartedAt),
		sess.stats.Requests,
		rrHumanBytes(sess.stats.UpBytes),
		rrHumanBytes(sess.stats.DownBytes),
		sess.stats.CloseSent,
		sess.stats.ClientClose,
		sess.stats.RemoteClose,
		0,
		sess.stats.OutOfOrder,
		sess.stats.WriteErrs,
		sess.stats.ReadErrs,
		sess.stats.Non200,
		sess.stats.LastErr,
	)
}

type rrSession struct {
	mu sync.Mutex

	sid [16]byte
	tcp net.Conn

	lastSeen time.Time

	lastCSeq uint32
	nextSSeq uint32

	pendingSeq  uint32
	pendingData []byte

	clientClosed bool
	serverClosed bool

	stats         rrServerSessionStats
	summaryLogged bool
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

	now := time.Now()
	sess := &rrSession{
		sid:      sid,
		tcp:      tcp,
		lastSeen: now,
		stats: rrServerSessionStats{
			StartedAt: now,
		},
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

func (s *rrSessionStore) startJanitor(ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	interval := 10 * time.Second
	if ttl < interval {
		interval = ttl / 2
		if interval <= 0 {
			interval = time.Second
		}
	}

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		for range t.C {
			var victims [][16]byte

			s.mu.Lock()
			for sid, sess := range s.sessions {
				sess.mu.Lock()
				stale := time.Since(sess.lastSeen) > ttl
				sess.mu.Unlock()
				if stale {
					victims = append(victims, sid)
				}
			}
			s.mu.Unlock()

			for _, sid := range victims {
				log.Printf("rr sid=%s cleanup ttl=%s", rrSIDString(sid), ttl)
				s.remove(sid)
			}
		}
	}()
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
			log.Printf(
				"reqid=%s rr sid=%s gone remote=%s cseq=%d cack=%d flags=0x%02x",
				reqID, sidText, r.RemoteAddr, req.CSeq, req.CAck, req.Flags,
			)
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
	sess.stats.Requests++

	if sess.pendingSeq != 0 && req.CAck >= sess.pendingSeq {
		sess.pendingSeq = 0
		sess.pendingData = nil
	}

	if len(req.Data) > 0 {
		switch {
		case req.CSeq == sess.lastCSeq+1:
			if store.ioTimeout > 0 {
				_ = sess.tcp.SetWriteDeadline(time.Now().Add(store.ioTimeout))
			}
			if err = writeFull(sess.tcp, req.Data); err != nil {
				sess.stats.WriteErrs++
				sess.stats.Non200++
				sess.stats.LastErr = err.Error()
				log.Printf("reqid=%s rr sid=%s upstream write err=%v", reqID, sidText, err)
				fatalErr = fmt.Errorf("rr upstream write failed sid=%s: %w", sidText, err)
				fatalStatus = http.StatusBadGateway
				removeSession = true
			} else {
				sess.lastCSeq = req.CSeq
				sess.stats.UpBytes += int64(len(req.Data))
			}
		case req.CSeq <= sess.lastCSeq:
		default:
			sess.stats.OutOfOrder++
			sess.stats.Non200++
			sess.stats.LastErr = fmt.Sprintf("rr out of order sid=%s cseq=%d last=%d", sidText, req.CSeq, sess.lastCSeq)
			log.Printf("reqid=%s rr sid=%s out_of_order cseq=%d last=%d", reqID, sidText, req.CSeq, sess.lastCSeq)
			fatalErr = fmt.Errorf("rr out of order sid=%s cseq=%d last=%d", sidText, req.CSeq, sess.lastCSeq)
			fatalStatus = http.StatusConflict
		}
	}

	if fatalErr == nil && req.Flags&rrFlagClose != 0 && !sess.clientClosed {
		sess.clientClosed = true
		sess.stats.ClientClose++
		if tc, ok := sess.tcp.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	if fatalErr == nil {
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
				sess.stats.DownBytes += int64(n)
			}

			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				} else {
					sess.serverClosed = true
					if errors.Is(readErr, io.EOF) {
						sess.stats.RemoteClose++
						log.Printf("reqid=%s rr sid=%s remote close", reqID, sidText)
					} else {
						sess.stats.ReadErrs++
						sess.stats.LastErr = readErr.Error()
						log.Printf("reqid=%s rr sid=%s upstream read err=%v", reqID, sidText, readErr)
					}
				}
			}
		}

		if sess.serverClosed {
			resp.Flags |= rrFlagClose
			if sess.stats.CloseSent == 0 {
				sess.stats.CloseSent++
				log.Printf("reqid=%s rr sid=%s send close sseq=%d", reqID, sidText, resp.SSeq)
				rrServerLogSummaryLocked(sidText, sess)
			}
		}
	}

	if fatalErr != nil && removeSession {
		rrServerLogSummaryLocked(sidText, sess)
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
