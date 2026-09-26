package telemetry

import (
	"sync"
	"testing"
	"time"
)

func TestBroadcastIsNonBlockingWithSaturatedSubscriber(t *testing.T) {
	broker := NewBroker()
	client := broker.Subscribe()
	defer broker.Unsubscribe(client)

	for len(client) < cap(client) {
		client <- Event{}
	}

	done := make(chan struct{})
	go func() {
		broker.Broadcast(Event{Reason: "dropped"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Broadcast blocked with a saturated subscriber")
	}
}

func TestBroadcastDeliversQueuedEvent(t *testing.T) {
	broker := NewBroker()
	client := broker.Subscribe()
	defer broker.Unsubscribe(client)

	broker.Broadcast(Event{Reason: "queued"})

	select {
	case event := <-client:
		if event.Reason != "queued" {
			t.Fatalf("expected queued event, got %q", event.Reason)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for queued event")
	}
}

func TestBroadcastDeliversToMultipleSubscribers(t *testing.T) {
	broker := NewBroker()
	first := broker.Subscribe()
	second := broker.Subscribe()
	defer broker.Unsubscribe(first)
	defer broker.Unsubscribe(second)

	broker.Broadcast(Event{Reason: "fanout"})

	for name, client := range map[string]chan Event{"first": first, "second": second} {
		select {
		case event := <-client:
			if event.Reason != "fanout" {
				t.Fatalf("%s subscriber received %q", name, event.Reason)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %s subscriber", name)
		}
	}
}

func TestUnsubscribeIsSafeWhileDispatching(t *testing.T) {
	broker := NewBroker()
	client := broker.Subscribe()

	var broadcasts sync.WaitGroup
	broadcasts.Add(1)
	go func() {
		defer broadcasts.Done()
		for i := 0; i < 1000; i++ {
			broker.Broadcast(Event{Status: i})
		}
	}()

	broker.Unsubscribe(client)
	broadcasts.Wait()
}

func TestConcurrentSubscribeUnsubscribeAndBroadcast(t *testing.T) {
	broker := NewBroker()
	var work sync.WaitGroup

	for i := 0; i < 4; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			for j := 0; j < 500; j++ {
				broker.Broadcast(Event{Status: j})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			for j := 0; j < 100; j++ {
				client := broker.Subscribe()
				broker.Unsubscribe(client)
			}
		}()
	}

	work.Wait()
}

func TestSubscriberLifecycleDropsEventsFromZeroSubscriberPeriod(t *testing.T) {
	broker := NewBroker()
	broker.Broadcast(Event{Reason: "stale-before-subscribe"})

	first := broker.Subscribe()
	select {
	case event := <-first:
		t.Fatalf("received stale event after subscribe: %q", event.Reason)
	case <-time.After(20 * time.Millisecond):
	}

	broker.Unsubscribe(first)
	broker.Broadcast(Event{Reason: "stale-between-subscribers"})

	second := broker.Subscribe()
	defer broker.Unsubscribe(second)
	select {
	case event := <-second:
		t.Fatalf("received stale event after subscriber gap: %q", event.Reason)
	case <-time.After(20 * time.Millisecond):
	}

	broker.Broadcast(Event{Reason: "current"})
	select {
	case event := <-second:
		if event.Reason != "current" {
			t.Fatalf("expected current event, got %q", event.Reason)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for current event")
	}
}
