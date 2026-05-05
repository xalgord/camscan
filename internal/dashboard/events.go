package dashboard

import (
	"encoding/json"
	"sync"
	"time"
)

// EventType classifies dashboard events.
type EventType string

const (
	EventScanStart      EventType = "scan_start"
	EventCameraFound    EventType = "camera_found"
	EventAnalysis       EventType = "analysis"
	EventAnalysisDetail EventType = "analysis_detail" // Full structured analysis payload
	EventAlertSent      EventType = "alert_sent"
	EventScanComplete   EventType = "scan_complete"
	EventLog            EventType = "log"
	EventStats          EventType = "stats"
)

// Event is a structured dashboard event sent via SSE.
type Event struct {
	Type      EventType   `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Stats holds live scan statistics.
type Stats struct {
	TotalScans      int `json:"total_scans"`
	TotalCameras    int `json:"total_cameras"`
	TotalAlerts     int `json:"total_alerts"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Errors          int `json:"errors"`
	ActiveScan      bool   `json:"active_scan"`
	CurrentQuery    string `json:"current_query"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
}

// Hub manages SSE client connections and broadcasts events.
type Hub struct {
	mu        sync.RWMutex
	clients   map[chan []byte]struct{}
	stats     Stats
	history   [][]byte // recent events for new clients
	startTime time.Time
}

// NewHub creates a new event hub.
func NewHub() *Hub {
	return &Hub{
		clients:   make(map[chan []byte]struct{}),
		history:   make([][]byte, 0, 200),
		startTime: time.Now(),
	}
}

// Subscribe adds a new SSE client and returns its channel + cleanup func.
func (h *Hub) Subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}

	// Send history to new client
	for _, msg := range h.history {
		select {
		case ch <- msg:
		default:
		}
	}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		delete(h.clients, ch)
		close(ch)
		h.mu.Unlock()
	}
}

// Broadcast sends an event to all connected clients.
func (h *Hub) Broadcast(event Event) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	h.mu.Lock()
	// Keep last 200 events for history replay
	if len(h.history) >= 200 {
		h.history = h.history[1:]
	}
	h.history = append(h.history, data)

	for ch := range h.clients {
		select {
		case ch <- data:
		default:
			// Client too slow, skip
		}
	}
	h.mu.Unlock()
}

// Emit is a convenience method: type + data → broadcast.
func (h *Hub) Emit(t EventType, data interface{}) {
	h.Broadcast(Event{Type: t, Data: data})
}

// UpdateStats atomically updates stats and broadcasts them.
func (h *Hub) UpdateStats(fn func(s *Stats)) {
	h.mu.Lock()
	fn(&h.stats)
	h.stats.UptimeSeconds = int64(time.Since(h.startTime).Seconds())
	statsCopy := h.stats
	h.mu.Unlock()
	h.Emit(EventStats, statsCopy)
}

// GetStats returns a copy of current stats.
func (h *Hub) GetStats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.stats
	s.UptimeSeconds = int64(time.Since(h.startTime).Seconds())
	return s
}
