// wsgw_v1_lite.go
// WS server -> TCP upstream bridge (binary frames).
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

type frameInfo struct {
	frameNo int
	n       int
	hex     string
	at      time.Time
}

type lastFrames struct {
	mu       sync.Mutex
	ws2tcp   frameInfo
	tcp2ws   frameInfo
	ws2tcpOk bool
	tcp2wsOk bool
}

func (l *lastFrames) setWS2TCP(frameNo int, b []byte, hexN int) {
	l.mu.Lock()
	l.ws2tcp = frameInfo{frameNo: frameNo, n: len(b), hex: hexdumpN(b, hexN), at: time.Now()}
	l.ws2tcpOk = true
	l.mu.Unlock()
}
func (l *lastFrames) setTCP2WS(frameNo int, b []byte, hexN int) {
	l.mu.Lock()
	l.tcp2ws = frameInfo{frameNo: frameNo, n: len(b), hex: hexdumpN(b, hexN), at: time.Now()}
	l.tcp2wsOk = true
	l.mu.Unlock()
}
func (l *lastFrames) snapshot() (ws2tcp frameInfo, ws2tcpOk bool, tcp2ws frameInfo, tcp2wsOk bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ws2tcp, l.ws2tcpOk, l.tcp2ws, l.tcp2wsOk
}

type safeWS struct {
	c *websocket.Conn
	m sync.Mutex

	sid      string
	debug    bool
	hexN     int
	slowWarn time.Duration
	slowCrit time.Duration
}

func (w *safeWS) setWriteDeadline(d time.Time) {
	w.m.Lock()
	_ = w.c.SetWriteDeadline(d)
	w.m.Unlock()
}

func (w *safeWS) writeBinary(p []byte, deadline time.Time, dir string, frameNo int) (time.Duration, error) {
	w.m.Lock()
	defer w.m.Unlock()

	_ = w.c.SetWriteDeadline(deadline)
	t0 := time.Now()
	err := w.c.WriteMessage(websocket.BinaryMessage, p)
	dt := time.Since(t0)

	if w.debug && w.slowWarn > 0 && dt > w.slowWarn {
		lvl := "SLOW"
		if w.slowCrit > 0 && dt > w.slowCrit {
			lvl = "STALL"
		}
		log.Printf("sid=%s %s ws_write dir=%s frame#%d len=%d dt=%s hex=%s",
			w.sid, lvl, dir, frameNo, len(p), dt.Truncate(time.Microsecond), hexdumpN(p, w.hexN))
	}
	return dt, err
}

func (w *safeWS) writePing(deadline time.Time, pingNo int) (time.Duration, error) {
	w.m.Lock()
	defer w.m.Unlock()

	t0 := time.Now()
	err := w.c.WriteControl(websocket.PingMessage, []byte("ping"), deadline)
	dt := time.Since(t0)

	if w.debug && w.slowWarn > 0 && dt > w.slowWarn {
		lvl := "SLOW"
		if w.slowCrit > 0 && dt > w.slowCrit {
			lvl = "STALL"
		}
		log.Printf("sid=%s %s ws_ping ping#%d dt=%s", w.sid, lvl, pingNo, dt.Truncate(time.Microsecond))
	}
	return dt, err
}

func (w *safeWS) writeClose(code int, text string) (time.Duration, error) {
	w.m.Lock()
	defer w.m.Unlock()

	t0 := time.Now()
	err := w.c.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, text),
		time.Now().Add(2*time.Second),
	)
	dt := time.Since(t0)

	if w.debug {
		log.Printf("sid=%s ws_close_send code=%d text=%q dt=%s", w.sid, code, text, dt.Truncate(time.Microsecond))
	}
	return dt, err
}

// writeFull writes the whole buffer to c (handles short writes).
func writeFull(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if n > 0 {
			b = b[n:]
			if len(b) == 0 {
				return nil
			}
			if err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	return nil
}

func hexdumpN(b []byte, n int) string {
	if n <= 0 {
		return ""
	}
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

func clampInt(x, lo, hi int) int {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func uvarintLen(x int) int {
	if x < 0 {
		return 10
	}
	ux := uint64(x)
	n := 1
	for ux >= 0x80 {
		ux >>= 7
		n++
	}
	return n
}

// baseLen + 1(type) + uvarintLen(padN) + padN == target
func computePadLenToHitTarget(baseLen, target, maxPad int) (int, bool) {
	if target <= baseLen {
		return 0, false
	}
	// optimistic (varintLen=1)
	pad := target - baseLen - 2
	if pad <= 0 {
		return 0, false
	}
	if maxPad > 0 && pad > maxPad {
		return maxPad, false
	}
	for i := 0; i < 8; i++ {
		total := baseLen + 1 + uvarintLen(pad) + pad
		if total == target {
			return pad, true
		}
		pad += (target - total)
		if pad <= 0 {
			return 0, false
		}
		if maxPad > 0 && pad > maxPad {
			return maxPad, false
		}
	}
	return pad, false
}

var padPoolOnce sync.Once
var padPool []byte

func initPadPool() {
	padPoolOnce.Do(func() {
		padPool = make([]byte, 8*1024)
		_, _ = io.ReadFull(crand.Reader, padPool)
	})
}

// fastRandN returns uniform-ish [0..n-1] using crypto/rand.
func fastRandN(n int) int {
	if n <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = crand.Read(b[:])
	return int(binary.LittleEndian.Uint32(b[:]) % uint32(n))
}

func appendPadExact(dst []byte, padN int) []byte {
	if padN <= 0 {
		return dst
	}
	initPadPool()
	if padN > len(padPool) {
		padN = len(padPool)
	}
	// vary offset to avoid repeating prefix
	offMax := len(padPool) - padN
	off := 0
	if offMax > 0 {
		off = fastRandN(offMax + 1)
	}
	return appendInner(dst, innerPAD, padPool[off:off+padN])
}

// chooseTargetAndPadServer applies:
// - firstN: try exact target [tmin..tmax] using ONE exact PAD record (cap=maxFirst)
// - else: quiet PAD 0..padMax (cap to 32 already enforced by main normalize)
func chooseTargetAndPadServer(dst []byte, frameNo int, firstN, tmin, tmax, maxFirst, padMax int) []byte {
	if firstN > 0 && frameNo <= firstN && tmax > 0 && maxFirst > 0 {

		if tmin < 0 {
			tmin = 0
		}
		if tmin > tmax {
			tmin, tmax = tmax, tmin
		}
		target := tmin
		if tmax > tmin {
			target = tmin + fastRandN(tmax-tmin+1)
		}
		base := len(dst)
		padN, ok := computePadLenToHitTarget(base, target, maxFirst)
		if ok && padN > 0 {
			return appendPadExact(dst, padN)
		}
		// if can't be exact -> fall back to quiet noise (do not create weird huge tails)
	}

	// quiet pad: 0..padMax (tiny)
	if padMax <= 0 {
		return dst
	}
	// deterministic cap is already done in main, but keep safe
	if padMax > 32 {
		padMax = 32
	}
	padN := fastRandN(padMax + 1)
	if padN <= 0 {
		return dst
	}
	initPadPool()
	if padN > len(padPool) {
		padN = len(padPool)
	}
	offMax := len(padPool) - padN
	off := 0
	if offMax > 0 {
		off = fastRandN(offMax + 1)
	}
	return appendInner(dst, innerPAD, padPool[off:off+padN])
}

type res struct {
	dir string
	err error
	at  time.Time
}

func unblock(tcp net.Conn, ws *websocket.Conn, sws *safeWS) {
	_ = tcp.SetReadDeadline(time.Now())
	_ = tcp.SetWriteDeadline(time.Now())
	_ = ws.SetReadDeadline(time.Now())
	sws.setWriteDeadline(time.Now())
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ---- H2 / RFC8441 helpers ----

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(secKey string) string {
	sum := sha1.Sum([]byte(secKey + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// h2Stream: адаптер HTTP/2 CONNECT stream -> io.ReadWriteCloser
// Read: из r.Body; Write: в ResponseWriter (DATA frames), с Flush.
type h2Stream struct {
	rc io.ReadCloser
	w  io.Writer
	f  http.Flusher
	bw *bufio.Writer
}

func (s *h2Stream) Read(p []byte) (int, error) { return s.rc.Read(p) }

// IMPORTANT: Do NOT Flush() here.
// wsutil.* may call Write() multiple times.
// If we flush inside Write(), we reintroduce multi-write patterns.
func (s *h2Stream) Write(p []byte) (int, error) {
	if s.bw == nil {
		s.bw = bufio.NewWriterSize(s.w, 64*1024+256)
	}
	return s.bw.Write(p)
}

func (s *h2Stream) Flush() error {
	if s.bw != nil {
		if err := s.bw.Flush(); err != nil {
			return err
		}
	}
	if s.f != nil {
		s.f.Flush()
	}
	return nil
}

func (s *h2Stream) Close() error { return s.rc.Close() }

func isH2WebSocketConnect(r *http.Request) bool {
	if r.ProtoMajor != 2 {
		return false
	}
	if r.Method != "CONNECT" {
		return false
	}
	// RFC8441: :protocol = websocket (needs GODEBUG=http2xconnect=1)
	return strings.EqualFold(r.Header.Get(":protocol"), "websocket")
}

// read whole WS message payload (wsutil.Reader + header, including continuation frames)
func readWholeWSMessageWSUtil(stream io.Reader, rd *wsutil.Reader, hdr ws.Header, maxBytes int64) ([]byte, error) {
	chunk, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(chunk)+64)
	msg = append(msg, chunk...)

	if maxBytes > 0 && int64(len(msg)) > maxBytes {
		return nil, fmt.Errorf("message too large: %d > %d", len(msg), maxBytes)
	}

	if hdr.Fin {
		return msg, nil
	}

	for {
		h2, e2 := rd.NextFrame()
		if e2 != nil {
			return nil, e2
		}
		if h2.OpCode != ws.OpContinuation {
			_, _ = io.Copy(io.Discard, rd)
			return msg, nil
		}
		more, e3 := io.ReadAll(rd)
		if e3 != nil {
			return nil, e3
		}
		msg = append(msg, more...)
		if maxBytes > 0 && int64(len(msg)) > maxBytes {
			return nil, fmt.Errorf("message too large: %d > %d", len(msg), maxBytes)
		}
		if h2.Fin {
			return msg, nil
		}
	}
}

func handleH2WSBridge(
	w http.ResponseWriter,
	r *http.Request,
	sid string,
	upstream string,
	ioTimeout time.Duration,
	readLimit int64,
	frameMax int,
	debug bool,
	innerProto bool,
	innerLenPad bool,
	lenPadMin int,
	padMax int,
	innerPingEvery time.Duration,
	padFirstN int,
	padTargetMin int,
	padTargetMax int,
	padFirstMax int,
) {
	secKey := r.Header.Get("Sec-WebSocket-Key")
	if secKey == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "bad websocket headers", http.StatusBadRequest)
		return
	}

	// RFC8441: ответ — 200 OK (не 101)
	w.Header().Set("Sec-WebSocket-Accept", wsAccept(secKey))
	w.WriteHeader(http.StatusOK)

	fl, _ := w.(http.Flusher)
	stream := &h2Stream{rc: r.Body, w: w, f: fl, bw: bufio.NewWriterSize(w, 64*1024+256)}
	defer stream.Close()

	tcp, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		log.Printf("sid=%s dial upstream FAIL %s err=%v", sid, upstream, err)
		return
	}
	defer tcp.Close()

	log.Printf("sid=%s open h2ws<->tcp upstream=%s remote=%s ioTimeout=%s frameMax=%d innerProto=%v innerLenPad=%v lenPadMin=%d padMax=%d innerPingEvery=%s",
		sid, upstream, r.RemoteAddr, ioTimeout, frameMax, innerProto, innerLenPad, lenPadMin, padMax, innerPingEvery)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resCh := make(chan res, 2)

	// H2-WS -> TCP
	go func() {
		var rd wsutil.Reader
		rd.State = ws.StateServerSide
		rd.Source = stream
		rd.CheckUTF8 = false

		frameNo := 0

		for {
			hdr, err := rd.NextFrame()
			if err != nil {
				resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("nextframe: %w", err), at: time.Now()}
				return
			}

			switch hdr.OpCode {
			case ws.OpPing:
				p, _ := io.ReadAll(&rd)
				_ = wsutil.WriteServerMessage(stream, ws.OpPong, p)
				_ = stream.Flush()
				continue

			case ws.OpClose:
				_, _ = io.Copy(io.Discard, &rd)
				resCh <- res{dir: "h2ws->tcp", err: nil, at: time.Now()}
				return
			}

			if hdr.OpCode != ws.OpBinary && hdr.OpCode != ws.OpText && hdr.OpCode != ws.OpContinuation {
				_, _ = io.Copy(io.Discard, &rd)
				continue
			}

			frameNo++

			if !innerProto {
				// raw streaming
				buf := make([]byte, 64*1024)
				for {
					n, rerr := rd.Read(buf)
					if n > 0 {
						if ioTimeout > 0 {
							_ = tcp.SetWriteDeadline(time.Now().Add(ioTimeout))
						}
						if ew := writeFull(tcp, buf[:n]); ew != nil {
							resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("tcp write: %w", ew), at: time.Now()}
							return
						}
					}
					if rerr != nil {
						if rerr == io.EOF {
							break
						}
						resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("ws read: %w", rerr), at: time.Now()}
						return
					}
				}
				continue
			}

			// innerProto: read whole message then parse inner records
			msg, e2 := readWholeWSMessageWSUtil(stream, &rd, hdr, readLimit)
			if e2 != nil {
				resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("read msg: %w", e2), at: time.Now()}
				return
			}

			for len(msg) > 0 {
				typ, p, consumed, perr := parseOneInner(msg)
				if perr != nil || consumed <= 0 {
					resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("inner parse: %v", perr), at: time.Now()}
					return
				}
				switch typ {
				case innerDATA:
					// CRITICAL: upstream must receive ONLY raw TCP bytes (no inner headers, no padding).
					dataOut := p
					if innerLenPad {
						real, uerr := unpackLenPad(p)
						if uerr != nil {
							resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("lenpad decode: %w", uerr), at: time.Now()}
							return
						}
						dataOut = real
					}

					if len(dataOut) > 0 {
						if ioTimeout > 0 {
							_ = tcp.SetWriteDeadline(time.Now().Add(ioTimeout))
						}
						if ew := writeFull(tcp, dataOut); ew != nil {
							resCh <- res{dir: "h2ws->tcp", err: fmt.Errorf("tcp write: %w", ew), at: time.Now()}
							return
						}
					}

				case innerPAD, innerPING:
					// ignore
				case innerCLOSE:
					resCh <- res{dir: "h2ws->tcp", err: nil, at: time.Now()}
					return
				default:
					if debug {
						log.Printf("sid=%s h2ws->tcp ignore inner typ=0x%02x len=%d", sid, typ, len(p))
					}
				}
				msg = msg[consumed:]
			}
		}
	}()

	// TCP -> H2-WS
	go func() {
		var lastInnerPing time.Time
		buf := make([]byte, 64*1024)
		frameNo := 0

		for {
			select {
			case <-ctx.Done():
				resCh <- res{dir: "tcp->h2ws", err: ctx.Err(), at: time.Now()}
				return
			default:
			}

			if ioTimeout > 0 {
				_ = tcp.SetReadDeadline(time.Now().Add(ioTimeout))
			}
			n, rerr := tcp.Read(buf)
			if n > 0 {
				payload := buf[:n]

				if innerProto {
					framePack := make([]byte, 0, n+96)

					dataRec := payload
					if innerLenPad {
						minP := lenPadMin
						if frameMax > 0 && minP > (frameMax+2) {
							minP = frameMax + 2
						}
						dataRec = packLenPad(payload, minP)
					}
					framePack = appendInner(framePack, innerDATA, dataRec)

					// SMART PAD:
					// - first padFirstN outgoing frames: try exact target [padTargetMin..padTargetMax]
					// - after that: quiet pad 0..padMax
					frameNo++
					framePack = chooseTargetAndPadServer(framePack, frameNo, padFirstN, padTargetMin, padTargetMax, padFirstMax, padMax)

					// optional logical ping inside payload
					if innerPingEvery > 0 {
						if lastInnerPing.IsZero() || time.Since(lastInnerPing) >= innerPingEvery {
							framePack = appendInner(framePack, innerPING, nil)
							lastInnerPing = time.Now()
						}
					}

					payload = framePack

					// one WS message
					if err := wsutil.WriteServerBinary(stream, payload); err != nil {
						resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws write(inner): %w", err), at: time.Now()}
						return
					}
					if err := stream.Flush(); err != nil {
						resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws flush(inner): %w", err), at: time.Now()}
						return
					}

				} else {
					// raw mode: keep current chunking into continuation frames
					off := 0
					first := true
					for off < n {
						end := off + frameMax
						if end > n {
							end = n
						}
						chunk := buf[off:end]

						if first {
							if err := wsutil.WriteServerBinary(stream, chunk); err != nil {
								resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws write: %w", err), at: time.Now()}
								return
							}
							if err := stream.Flush(); err != nil {
								resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws flush: %w", err), at: time.Now()}
								return
							}
							first = false
						} else {
							if err := wsutil.WriteServerMessage(stream, ws.OpContinuation, chunk); err != nil {
								resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws write cont: %w", err), at: time.Now()}
								return
							}
							if err := stream.Flush(); err != nil {
								resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("ws flush cont: %w", err), at: time.Now()}
								return
							}
						}
						off = end
					}
				}
			}

			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					resCh <- res{dir: "tcp->h2ws", err: nil, at: time.Now()}
					return
				}
				resCh <- res{dir: "tcp->h2ws", err: fmt.Errorf("tcp read: %w", rerr), at: time.Now()}
				return
			}
		}
	}()

	r1 := <-resCh
	if debug {
		log.Printf("sid=%s done dir=%s err=%v at=%s", sid, r1.dir, r1.err, r1.at.Format(time.RFC3339Nano))
	}
	if r1.err != nil {
		cancel()
	}
	r2 := <-resCh
	if debug {
		log.Printf("sid=%s done dir=%s err=%v at=%s", sid, r2.dir, r2.err, r2.at.Format(time.RFC3339Nano))
	}

	bridgeErr := r1.err
	if bridgeErr == nil {
		bridgeErr = r2.err
	}
	log.Printf("sid=%s close(h2ws) err=%v r1=%s:%v r2=%s:%v",
		sid, bridgeErr, r1.dir, r1.err, r2.dir, r2.err)
}

// ---- main ----

func main() {
	var listen string
	var path string
	var upstream string
	var ioTimeout time.Duration
	var readLimit int64
	var frameMax int
	var pingEvery time.Duration
	var debug bool

	var tlsCert string
	var tlsKey string

	var hexN int
	var hexFrames int
	var slowWarn time.Duration
	var slowCrit time.Duration

	// inner framing (server side)
	var innerProto bool
	var innerLenPad bool
	var lenPadMin int
	var padMax int
	var innerPingEvery time.Duration

	// smart padding (server side, tcp->ws / tcp->h2ws)
	var padFirstN int
	var padTargetMin int
	var padTargetMax int
	var padFirstMax int

	flag.StringVar(&listen, "listen", "127.0.0.1:5003", "HTTP listen address")
	flag.StringVar(&path, "path", "/ws", "WebSocket path prefix")
	flag.StringVar(&upstream, "upstream", "127.0.0.1:5000", "Upstream TCP address")
	flag.DurationVar(&ioTimeout, "ioTimeout", 30*time.Second, "I/O idle timeout")
	flag.Int64Var(&readLimit, "readLimit", 2<<20, "WebSocket read limit (bytes per message)")
	flag.IntVar(&frameMax, "frameMax", 32768, "Max bytes per DATA frame")
	flag.DurationVar(&pingEvery, "ping", 20*time.Second, "WS ping interval (0 disables)")
	flag.BoolVar(&debug, "debug", false, "Verbose logs")

	flag.StringVar(&tlsCert, "tlsCert", "", "TLS cert path (enable HTTPS/H2 when set)")
	flag.StringVar(&tlsKey, "tlsKey", "", "TLS key path (enable HTTPS/H2 when set)")

	flag.IntVar(&hexN, "hexN", 64, "Hexdump first N bytes per WS frame (debug)")
	flag.IntVar(&hexFrames, "hexFrames", 6, "Hexdump first N WS frames per direction (debug)")
	flag.DurationVar(&slowWarn, "slowWriteWarn", 50*time.Millisecond, "Log write dt > this (debug). 0 disables")
	flag.DurationVar(&slowCrit, "slowWriteCrit", 200*time.Millisecond, "Escalate to STALL if write dt > this (debug). 0 disables")

	// inner framing flags
	flag.BoolVar(&innerProto, "innerProto", false, "expect/send inner framing inside WS payload")
	flag.BoolVar(&innerLenPad, "innerLenPad", false, "innerDATA payload is [u16 realLen][data][zero padding]; bridge strips padding")
	flag.IntVar(&lenPadMin, "lenPadMin", 0, "when innerLenPad: pad innerDATA to at least this many bytes total (including 2-byte header). 0 disables padding")
	flag.IntVar(&padMax, "padMax", 0, "random padding per inner message (0 disables, max 32)")
	flag.DurationVar(&innerPingEvery, "innerPingEvery", 0, "logical ping inside payload each N (0 disables)")

	// smart padding flags (first N outgoing WS frames: hit target size by exact PAD record)
	flag.IntVar(&padFirstN, "padFirstN", 8, "smart padding: apply target sizing for first N outgoing WS frames (0 disables)")
	flag.IntVar(&padTargetMin, "padTargetMin", 600, "smart padding: target payload min for first N outgoing frames")
	flag.IntVar(&padTargetMax, "padTargetMax", 1400, "smart padding: target payload max for first N outgoing frames")
	flag.IntVar(&padFirstMax, "padFirstMax", 1400, "smart padding: max PAD payload bytes allowed for first N outgoing frames")

	flag.Parse()

	if frameMax < 512 {
		frameMax = 512
	}
	if hexFrames < 0 {
		hexFrames = 0
	}

	// normalize inner knobs
	if padMax < 0 {
		padMax = 0
	}
	if padMax > 32 {
		padMax = 32
	}

	if lenPadMin < 0 {
		lenPadMin = 0
	}
	// absolute max for safety
	if lenPadMin > (64*1024 + 2) {
		lenPadMin = 64*1024 + 2
	}

	// normalize smart padding knobs
	if padFirstN < 0 {
		padFirstN = 0
	}
	if padTargetMin < 0 {
		padTargetMin = 0
	}
	if padTargetMax < 0 {
		padTargetMax = 0
	}
	if padTargetMin > padTargetMax {
		padTargetMin, padTargetMax = padTargetMax, padTargetMin
	}
	if padFirstMax < 0 {
		padFirstMax = 0
	}
	// safety cap
	if padFirstMax > 8192 {
		padFirstMax = 8192
	}
	// if enabled but meaningless -> disable
	if padFirstN > 0 {
		if padTargetMax <= 0 || padFirstMax == 0 {
			padFirstN = 0
		}
	}

	// lenpad implies inner framing
	if innerLenPad {
		innerProto = true
	}
	if padMax > 0 || innerPingEvery > 0 || padFirstN > 0 {
		innerProto = true
	}

	mux := http.NewServeMux()
	var sidCtr uint64

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !(r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/")) {
			http.NotFound(w, r)
			return
		}

		sid := fmt.Sprintf("%08x-%08x", atomic.AddUint64(&sidCtr, 1), uint32(time.Now().UnixNano()))

		// HTTP/2 WebSocket (RFC8441 extended CONNECT)
		if isH2WebSocketConnect(r) {
			handleH2WSBridge(
				w, r, sid, upstream, ioTimeout, readLimit, frameMax, debug,
				innerProto, innerLenPad, lenPadMin, padMax, innerPingEvery,
				padFirstN, padTargetMin, padTargetMax, padFirstMax,
			)
			return
		}

		// HTTP/1.1 WebSocket Upgrade
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("upgrade error: %v", err)
			return
		}
		defer wsConn.Close()

		wsConn.SetReadLimit(readLimit)

		ua := r.Header.Get("User-Agent")
		remote := r.RemoteAddr

		// counters + last-frame cache
		var w2tBytes int64
		var t2wBytes int64
		var wsIn int64
		var tcpOut int64
		var wsFramesIn int64
		var wsFramesOut int64
		var last lastFrames

		wsConn.SetCloseHandler(func(code int, text string) error {
			log.Printf("sid=%s ws CLOSE recv code=%d text=%q frames_in=%d frames_out=%d ws_in=%d tcp_out=%d bytes_w2t=%d bytes_t2w=%d",
				sid, code, text,
				atomic.LoadInt64(&wsFramesIn), atomic.LoadInt64(&wsFramesOut),
				atomic.LoadInt64(&wsIn), atomic.LoadInt64(&tcpOut),
				atomic.LoadInt64(&w2tBytes), atomic.LoadInt64(&t2wBytes))
			return nil
		})
		wsConn.SetPongHandler(func(appData string) error {
			if debug {
				log.Printf("sid=%s ws PONG %q", sid, appData)
			}
			return nil
		})

		tcp, err := net.DialTimeout("tcp", upstream, 5*time.Second)
		if err != nil {
			log.Printf("sid=%s dial upstream FAIL %s err=%v", sid, upstream, err)
			return
		}
		defer tcp.Close()

		log.Printf("sid=%s open ws(h1)<->tcp upstream=%s ua=%q remote=%s ioTimeout=%s frameMax=%d ping=%s innerProto=%v innerLenPad=%v lenPadMin=%d padMax=%d innerPingEvery=%s debug=%v hexN=%d hexFrames=%d slowWarn=%s slowCrit=%s",
			sid, upstream, ua, remote, ioTimeout, frameMax, pingEvery, innerProto, innerLenPad, lenPadMin, padMax, innerPingEvery, debug, hexN, hexFrames, slowWarn, slowCrit)

		sws := &safeWS{c: wsConn, sid: sid, debug: debug, hexN: hexN, slowWarn: slowWarn, slowCrit: slowCrit}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// ping loop (serialized)
		if pingEvery > 0 {
			go func() {
				t := time.NewTicker(pingEvery)
				defer t.Stop()
				pingNo := 0
				for {
					select {
					case <-t.C:
					case <-ctx.Done():
						return
					}
					pingNo++
					dl := time.Now().Add(5 * time.Second)
					if _, err := sws.writePing(dl, pingNo); err != nil {
						log.Printf("sid=%s ping FAIL err=%v", sid, err)
						cancel()
						return
					}
					if debug {
						log.Printf("sid=%s ping OK ping#%d", sid, pingNo)
					}
				}
			}()
		}

		resCh := make(chan res, 2)

		// ws -> tcp
		go func() {
			frameNo := 0
			for {
				if ioTimeout > 0 {
					_ = wsConn.SetReadDeadline(time.Now().Add(ioTimeout))
				}

				mt, rws, rerr := wsConn.NextReader()
				if rerr != nil {
					resCh <- res{dir: "ws->tcp", err: fmt.Errorf("ws->tcp nextreader: %w", rerr), at: time.Now()}
					return
				}
				if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
					if debug {
						log.Printf("sid=%s ws->tcp skip mt=%d", sid, mt)
					}
					continue
				}

				frameNo++
				atomic.AddInt64(&wsFramesIn, 1)

				if !innerProto {
					// raw streaming
					if ioTimeout > 0 {
						_ = tcp.SetWriteDeadline(time.Now().Add(ioTimeout))
					}
					buf := make([]byte, 64*1024)
					tw0 := time.Now()
					n64, werr := io.CopyBuffer(tcp, rws, buf)
					dt := time.Since(tw0)

					if werr != nil {
						resCh <- res{dir: "ws->tcp", err: fmt.Errorf("ws->tcp copy frame#%d n=%d dt=%s: %w",
							frameNo, n64, dt.Truncate(time.Microsecond), werr), at: time.Now()}
						return
					}

					atomic.AddInt64(&w2tBytes, n64)
					atomic.AddInt64(&wsIn, n64)
					atomic.AddInt64(&tcpOut, n64)

					if debug && slowWarn > 0 && dt > slowWarn {
						lvl := "SLOW"
						if slowCrit > 0 && dt > slowCrit {
							lvl = "STALL"
						}
						log.Printf("sid=%s %s ws->tcp copy frame#%d n=%d dt=%s",
							sid, lvl, frameNo, n64, dt.Truncate(time.Microsecond))
					}
					continue
				}

				// innerProto: read entire WS message then parse records
				msg, e2 := io.ReadAll(rws)
				if e2 != nil {
					resCh <- res{dir: "ws->tcp", err: fmt.Errorf("inner read frame#%d: %w", frameNo, e2), at: time.Now()}
					return
				}
				last.setWS2TCP(frameNo, msg, hexN)

				for len(msg) > 0 {
					typ, p, consumed, perr := parseOneInner(msg)
					if perr != nil || consumed <= 0 {
						resCh <- res{dir: "ws->tcp", err: fmt.Errorf("inner parse frame#%d: %v", frameNo, perr), at: time.Now()}
						return
					}

					switch typ {
					case innerDATA:
						// CRITICAL: upstream must receive ONLY raw TCP bytes (no inner headers, no padding).
						dataOut := p
						if innerLenPad {
							real, uerr := unpackLenPad(p)
							if uerr != nil {
								resCh <- res{dir: "ws->tcp", err: fmt.Errorf("lenpad decode frame#%d: %w", frameNo, uerr), at: time.Now()}
								return
							}
							dataOut = real
						}

						if len(dataOut) > 0 {
							if ioTimeout > 0 {
								_ = tcp.SetWriteDeadline(time.Now().Add(ioTimeout))
							}
							if ew := writeFull(tcp, dataOut); ew != nil {
								resCh <- res{dir: "ws->tcp", err: fmt.Errorf("tcp write: %w", ew), at: time.Now()}
								return
							}
							atomic.AddInt64(&w2tBytes, int64(len(dataOut)))
							atomic.AddInt64(&wsIn, int64(len(dataOut)))
							atomic.AddInt64(&tcpOut, int64(len(dataOut)))
						}

					case innerPAD, innerPING:
						// ignore

					case innerCLOSE:
						resCh <- res{dir: "ws->tcp", err: nil, at: time.Now()}
						return

					default:
						if debug {
							log.Printf("sid=%s ws->tcp ignore inner typ=0x%02x len=%d frame#%d", sid, typ, len(p), frameNo)
						}
					}

					msg = msg[consumed:]
				}
			}
		}()

		// tcp -> ws
		go func() {
			var lastInnerPing time.Time

			buf := make([]byte, 64*1024)
			frameNo := 0

			for {
				if ioTimeout > 0 {
					_ = tcp.SetReadDeadline(time.Now().Add(ioTimeout))
				}
				n, rerr := tcp.Read(buf)

				if n > 0 {
					frameNo++
					atomic.AddInt64(&wsFramesOut, 1)
					atomic.AddInt64(&t2wBytes, int64(n))

					payload := buf[:n]

					if innerProto {
						framePack := make([]byte, 0, n+96)

						// DATA (len+data+optional zero pad)
						dataRec := payload
						if innerLenPad {
							// format always [len][data], padding controlled by lenPadMin
							minP := lenPadMin
							// keep sane: don't make it bigger than what you typically send in one frame
							if frameMax > 0 && minP > (frameMax+2) {
								minP = frameMax + 2
							}
							dataRec = packLenPad(payload, minP)
						}
						framePack = appendInner(framePack, innerDATA, dataRec)

						// SMART PAD:
						// - first padFirstN outgoing frames: try exact target [padTargetMin..padTargetMax]
						// - after that: quiet pad 0..padMax
						framePack = chooseTargetAndPadServer(framePack, frameNo, padFirstN, padTargetMin, padTargetMax, padFirstMax, padMax)

						// optional logical ping inside payload
						if innerPingEvery > 0 {
							if lastInnerPing.IsZero() || time.Since(lastInnerPing) >= innerPingEvery {
								framePack = appendInner(framePack, innerPING, nil)
								lastInnerPing = time.Now()
							}
						}

						payload = framePack
					}

					dl := time.Now().Add(ioTimeout)
					if ioTimeout <= 0 {
						dl = time.Now().Add(10 * time.Second)
					}

					if innerProto {
						last.setTCP2WS(frameNo, payload, hexN)
						if _, werr := sws.writeBinary(payload, dl, "tcp->ws", frameNo); werr != nil {
							resCh <- res{dir: "tcp->ws", err: fmt.Errorf("tcp->ws write(inner) frame#%d len=%d: %w",
								frameNo, len(payload), werr), at: time.Now()}
							return
						}
					} else {
						// RAW: one WS message per tcp read, streaming via NextWriter + chunking
						last.setTCP2WS(frameNo, buf[:n], hexN)

						sws.m.Lock()
						_ = wsConn.SetWriteDeadline(dl)
						wr, werr := wsConn.NextWriter(websocket.BinaryMessage)
						if werr == nil {
							off := 0
							for off < n {
								end := off + frameMax
								if end > n {
									end = n
								}
								if _, ew := wr.Write(buf[off:end]); ew != nil {
									werr = ew
									break
								}
								off = end
							}
							if cerr := wr.Close(); werr == nil && cerr != nil {
								werr = cerr
							}
						}
						_ = wsConn.SetWriteDeadline(time.Time{})
						sws.m.Unlock()

						if werr != nil {
							resCh <- res{dir: "tcp->ws", err: fmt.Errorf("tcp->ws nextwriter frame#%d len=%d: %w",
								frameNo, n, werr), at: time.Now()}
							return
						}
					}
				}

				if rerr != nil {
					if errors.Is(rerr, io.EOF) {
						resCh <- res{dir: "tcp->ws", err: nil, at: time.Now()}
						return
					}
					resCh <- res{dir: "tcp->ws", err: fmt.Errorf("tcp->ws read: %w", rerr), at: time.Now()}
					return
				}
			}
		}()

		// Wait both directions. If one fails fatally -> cancel + unblock the other.
		r1 := <-resCh
		if debug {
			log.Printf("sid=%s done dir=%s err=%v at=%s", sid, r1.dir, r1.err, r1.at.Format(time.RFC3339Nano))
		}
		if r1.err != nil {
			cancel()
			unblock(tcp, wsConn, sws)
		}
		r2 := <-resCh
		if debug {
			log.Printf("sid=%s done dir=%s err=%v at=%s", sid, r2.dir, r2.err, r2.at.Format(time.RFC3339Nano))
		}

		bridgeErr := r1.err
		if bridgeErr == nil {
			bridgeErr = r2.err
		}

		wsInV := atomic.LoadInt64(&wsIn)
		tcpOutV := atomic.LoadInt64(&tcpOut)
		if wsInV != tcpOutV {
			log.Printf("sid=%s WARN ws_in!=tcp_out ws_in=%d tcp_out=%d (delta=%d)",
				sid, wsInV, tcpOutV, wsInV-tcpOutV)
		}

		ws2tcp, okA, tcp2ws, okB := last.snapshot()
		if okA {
			log.Printf("sid=%s last ws->tcp frame#%d len=%d hex=%s at=%s",
				sid, ws2tcp.frameNo, ws2tcp.n, ws2tcp.hex, ws2tcp.at.Format(time.RFC3339Nano))
		}
		if okB {
			log.Printf("sid=%s last tcp->ws frame#%d len=%d hex=%s at=%s",
				sid, tcp2ws.frameNo, tcp2ws.n, tcp2ws.hex, tcp2ws.at.Format(time.RFC3339Nano))
		}

		// Close control frame ONLY when both directions ended cleanly.
		if bridgeErr == nil {
			_, _ = sws.writeClose(websocket.CloseNormalClosure, "bye")
		} else if debug {
			log.Printf("sid=%s skip ws_close_send because err=%v", sid, bridgeErr)
		}

		log.Printf("sid=%s close err=%v ws_in=%d tcp_out=%d frames_in=%d frames_out=%d bytes_w2t=%d bytes_t2w=%d r1=%s:%v r2=%s:%v",
			sid, bridgeErr,
			wsInV, tcpOutV,
			atomic.LoadInt64(&wsFramesIn), atomic.LoadInt64(&wsFramesOut),
			atomic.LoadInt64(&w2tBytes), atomic.LoadInt64(&t2wBytes),
			r1.dir, r1.err, r2.dir, r2.err)
	})

	srv := &http.Server{Addr: listen, Handler: mux}

	// TLS => ALPN h2/http1 + HTTP/2 server
	if tlsCert != "" || tlsKey != "" {
		if tlsCert == "" || tlsKey == "" {
			log.Fatal("both -tlsCert and -tlsKey must be set")
		}
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		_ = http2.ConfigureServer(srv, &http2.Server{})
		log.Printf("NOTE: For RFC8441 (HTTP/2 WebSocket) run with env: GODEBUG=http2xconnect=1")
	}

	log.Printf("wsgw_lite listening=%s path=%s upstream=%s ioTimeout=%s readLimit=%d frameMax=%d ping=%s innerProto=%v innerLenPad=%v lenPadMin=%d padMax=%d innerPingEvery=%s debug=%v hexN=%d hexFrames=%d slowWarn=%s slowCrit=%s tls=%v",
		listen, path, upstream, ioTimeout, readLimit, frameMax, pingEvery, innerProto, innerLenPad, lenPadMin, padMax, innerPingEvery, debug, hexN, hexFrames, slowWarn, slowCrit, (tlsCert != ""))

	if tlsCert != "" {
		log.Fatal(srv.ListenAndServeTLS(tlsCert, tlsKey))
	}
	log.Fatal(srv.ListenAndServe())
}
