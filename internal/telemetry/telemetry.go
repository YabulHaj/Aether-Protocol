package telemetry

import (
	"sync"
)

const (
	telemetryQueueSize = 256
	clientQueueSize    = 50
)

// Event contains the exact data the Aether Live UI needs to render the animation.
type Event struct {
	ScenarioID string `json:"scenario_id,omitempty"`
	Identity   string `json:"identity"`
	Intent     string `json:"intent"`
	Capability string `json:"capability"`
	Target     string `json:"target"`
	Operation  string `json:"operation"`
	Reason     string `json:"reason"`
	Status     int    `json:"status"`
	Hash       string `json:"hash"`
	Allowed    bool   `json:"allowed"`
}

// Broker manages the connections to the web browser.
type Broker struct {
	clients map[chan Event]struct{}
	ingress chan Event
	mu      sync.Mutex
	worker  bool
	stop    chan struct{}
	done    chan struct{}
}

// NewBroker initializes a new telemetry hub.
func NewBroker() *Broker {
	return &Broker{
		clients: make(map[chan Event]struct{}),
		ingress: make(chan Event, telemetryQueueSize),
	}
}

// Subscribe adds a new web browser connection to the hub.
func (b *Broker) Subscribe() chan Event {
	clientChan := make(chan Event, clientQueueSize)

	for {
		b.mu.Lock()
		if b.worker || b.done == nil {
			break
		}
		done := b.done
		b.mu.Unlock()
		<-done
		b.mu.Lock()
		if b.done == done {
			b.done = nil
		}
		b.mu.Unlock()
	}

	if len(b.clients) == 0 {
		for {
			select {
			case <-b.ingress:
			default:
				goto drained
			}
		}
	}

drained:
	b.clients[clientChan] = struct{}{}
	if !b.worker {
		b.worker = true
		b.stop = make(chan struct{})
		b.done = make(chan struct{})
		go b.dispatch(b.stop, b.done)
	}
	b.mu.Unlock()

	return clientChan
}

// Unsubscribe removes the browser connection when the tab is closed.
func (b *Broker) Unsubscribe(clientChan chan Event) {
	b.mu.Lock()
	if _, ok := b.clients[clientChan]; ok {
		delete(b.clients, clientChan)
		close(clientChan)
		if len(b.clients) == 0 && b.worker {
			close(b.stop)
			b.worker = false
		}
	}
	b.mu.Unlock()
}

// Broadcast sends the authorization decision to the UI.
// CRITICAL ARCHITECTURE: The 'select' statement with a 'default' case
// ensures that if the browser is slow, the event is dropped.
// The gateway NEVER waits for the UI.
func (b *Broker) Broadcast(event Event) {
	select {
	case b.ingress <- event:
	default:
		// Drop telemetry when the bounded ingress queue is full.
	}
}

func (b *Broker) dispatch(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)

	for {
		select {
		case <-stop:
			return
		case event := <-b.ingress:
			b.mu.Lock()
			for clientChan := range b.clients {
				select {
				case clientChan <- event:
				default:
					// Drop events for a slow browser.
				}
			}
			b.mu.Unlock()
		}
	}
}
