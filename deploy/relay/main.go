// RNET Relay Server — minimal UDP/QUIC forwarder.
//
// Routes encrypted RNET transport frames between clients. The relay does not
// decrypt any traffic — it forwards opaque UDP datagrams based solely on the
// 4-byte session ID in the RNET frame header.
//
// Frame header layout (matches TransportFrame.kt / TransportFrame.swift):
//
//   Offset  Size  Field
//   ──────  ────  ─────────────────────────────────────────────
//   0       4     session_id  (uint32 big-endian)
//   4       4     sequence    (uint32 big-endian)
//   8       1     shard_index (uint8)
//   9       1     total_shards (uint8)
//   10      2     reserved    (uint16)
//   12+     n     payload     (AES-GCM ciphertext + tag)
//
// The relay inspects only bytes [0:4] (session ID) to route datagrams.
// Everything beyond byte 4 is forwarded unchanged.
//
// Build:  go build -o rnet-relay .
// Run:    ./rnet-relay --port 7777
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"sync"
	"time"
)

const (
	maxDatagramSize = 1500
	sessionTimeout  = 5 * time.Minute
)

type session struct {
	peers   [2]*net.UDPAddr
	peerIdx int
	lastSeen time.Time
	mu      sync.Mutex
}

type relay struct {
	conn     *net.UDPConn
	sessions sync.Map // sessionID uint32 → *session
}

func main() {
	port := flag.String("port", "7777", "UDP port to listen on")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp4", ":"+*port)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("RNET relay listening on UDP :%s", *port)

	r := &relay{conn: conn}
	go r.reapExpired()
	r.serve()
}

func (r *relay) serve() {
	buf := make([]byte, maxDatagramSize)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}
		if n < 12 {
			continue // too short to be a valid RNET frame
		}
		sessionID := binary.BigEndian.Uint32(buf[0:4])
		r.route(sessionID, src, buf[:n])
	}
}

func (r *relay) route(sessionID uint32, src *net.UDPAddr, frame []byte) {
	val, _ := r.sessions.LoadOrStore(sessionID, &session{lastSeen: time.Now()})
	sess := val.(*session)

	sess.mu.Lock()
	defer sess.mu.Unlock()

	sess.lastSeen = time.Now()

	// Register the source address in one of the two peer slots
	peerSlot := -1
	for i, p := range sess.peers {
		if p != nil && p.String() == src.String() {
			peerSlot = i
			break
		}
	}
	if peerSlot == -1 {
		// New peer — assign next available slot
		for i, p := range sess.peers {
			if p == nil {
				sess.peers[i] = src
				peerSlot = i
				log.Printf("session %08x: registered peer[%d] %s", sessionID, i, src)
				break
			}
		}
	}
	if peerSlot == -1 {
		return // session full (more than 2 peers)
	}

	// Forward to the other peer
	other := 1 - peerSlot
	if sess.peers[other] == nil {
		return // other peer not yet registered
	}
	_, _ = r.conn.WriteToUDP(frame, sess.peers[other])
}

func (r *relay) reapExpired() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		r.sessions.Range(func(k, v any) bool {
			sess := v.(*session)
			sess.mu.Lock()
			expired := now.Sub(sess.lastSeen) > sessionTimeout
			sess.mu.Unlock()
			if expired {
				r.sessions.Delete(k)
				log.Printf("session %08x expired", k.(uint32))
			}
			return true
		})
	}
}
