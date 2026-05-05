package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

//go:embed assets/index.html
var assetsFS embed.FS

// Server is the dashboard HTTP server.
type Server struct {
	hub  *Hub
	port int
}

// NewServer creates a new dashboard server on the given port.
func NewServer(hub *Hub, port int) *Server {
	return &Server{hub: hub, port: port}
}

// Start launches the dashboard HTTP server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()

	// Serve the dashboard HTML
	mux.HandleFunc("/", s.handleIndex)

	// SSE endpoint for real-time events
	mux.HandleFunc("/events", s.handleSSE)

	// REST endpoint for current stats
	mux.HandleFunc("/api/stats", s.handleStats)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Dashboard running at http://localhost%s", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("Dashboard server error: %v", err)
		}
	}()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "Dashboard not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch, cleanup := s.hub.Subscribe()
	defer cleanup()

	// Send initial stats
	stats := s.hub.GetStats()
	statsJSON, _ := json.Marshal(Event{Type: EventStats, Data: stats})
	fmt.Fprintf(w, "data: %s\n\n", statsJSON)
	flusher.Flush()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.hub.GetStats())
}
