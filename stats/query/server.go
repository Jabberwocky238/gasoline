package query

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/stats/ratelimiter"
	"github.com/jabberwocky238/gasoline/stats/recorder"
)

// Server provides an HTTP API for querying and managing the stats engine.
type Server struct {
	addr     string
	recorder *recorder.Recorder
	limiter  *ratelimiter.RateLimiter
	server   *http.Server
}

// New creates a query Server.
func New(addr string, rec *recorder.Recorder, rl *ratelimiter.RateLimiter) *Server {
	s := &Server{
		addr:     addr,
		recorder: rec,
		limiter:  rl,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/session/", s.handleSession)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/ratelimit", s.handleRateLimit)

	s.server = &http.Server{Addr: addr, Handler: mux}
	return s
}

// Start launches the HTTP server in a goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("stats API listen on %s: %w", s.addr, err)
	}
	log.Infof("Stats API listening on %s", ln.Addr())
	go s.server.Serve(ln)
	return nil
}

// Close shuts down the HTTP server.
func (s *Server) Close() error {
	return s.server.Shutdown(context.Background())
}

// GET /api/sessions — list all active sessions
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.recorder.All())
}

// GET /api/session/<hex_session_id> — get a single session's stats
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idHex := r.URL.Path[len("/api/session/"):]
	sessionID, err := parseID(idHex)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad session id: %v", err), http.StatusBadRequest)
		return
	}
	stats := s.recorder.Get(sessionID)
	if stats == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, stats)
}

// GET /api/stats — aggregate stats (total sessions, total bytes)
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tx, rx := s.recorder.TotalBytes()
	writeJSON(w, map[string]any{
		"active_sessions": s.recorder.Count(),
		"total_tx_bytes":  tx,
		"total_rx_bytes":  rx,
	})
}

// POST   /api/ratelimit?vnet=<hex>  body: {"bps": 1048576}
// GET    /api/ratelimit?vnet=<hex>   — query current rule
// GET    /api/ratelimit              — list all rules
// DELETE /api/ratelimit?vnet=<hex>   — remove rule
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	idHex := r.URL.Query().Get("vnet")
	if idHex == "" {
		if r.Method == http.MethodGet {
			rules := s.limiter.AllRules()
			out := make(map[string]uint64, len(rules))
			for id, rule := range rules {
				out[hex.EncodeToString(id[:])] = rule.BytesPerSecond
			}
			writeJSON(w, out)
			return
		}
		http.Error(w, "vnet param required", http.StatusBadRequest)
		return
	}

	vnetID, err := parseID(idHex)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad vnet id: %v", err), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule := s.limiter.GetRule(vnetID)
		if rule == nil {
			writeJSON(w, map[string]any{"bytes_per_second": 0, "limited": false})
		} else {
			writeJSON(w, map[string]any{"bytes_per_second": rule.BytesPerSecond, "limited": true})
		}

	case http.MethodPost:
		var body struct {
			BytesPerSecond uint64 `json:"bps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, fmt.Sprintf("bad body: %v", err), http.StatusBadRequest)
			return
		}
		s.limiter.SetRule(vnetID, &ratelimiter.Rule{BytesPerSecond: body.BytesPerSecond})
		writeJSON(w, map[string]string{"status": "ok"})

	case http.MethodDelete:
		s.limiter.Remove(vnetID)
		writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func parseID(hexStr string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return id, err
	}
	if len(b) > 16 {
		return id, fmt.Errorf("id too long: %d bytes", len(b))
	}
	copy(id[:], b)
	return id, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
