// Copyright 2016 Apcera Inc. All rights reserved.

package test

import (
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/go-nats"
)

func TestMultipleUserAuth(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/multi_user.conf")
	defer srv.Shutdown()

	if opts.Users == nil {
		t.Fatal("Expected a user array that is not nil")
	}
	if len(opts.Users) != 2 {
		t.Fatal("Expected a user array that had 2 users")
	}

	// Test first user
	url := fmt.Sprintf("nats://%s:%s@%s:%d/",
		opts.Users[0].Username,
		opts.Users[0].Password,
		opts.Host, opts.Port)

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	if !nc.AuthRequired() {
		t.Fatal("Expected auth to be required for the server")
	}

	// Test second user
	url = fmt.Sprintf("nats://%s:%s@%s:%d/",
		opts.Users[1].Username,
		opts.Users[1].Password,
		opts.Host, opts.Port)

	nc, err = nats.Connect(url)
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()
}

func TestRateLimiting(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/multi_user.conf")
	defer srv.Shutdown()

	if opts.Users == nil {
		t.Fatal("Expected a user array that is not nil")
	}
	if len(opts.Users) != 2 {
		t.Fatal("Expected a user array that had 2 users")
	}
	if opts.Users[0].MsgRate != 100 {
		t.Fatalf("Expected first user to have rate limit of 100, got %v", opts.Users[0].MsgRate)
	}

	// Use user with rate limit
	url := fmt.Sprintf("nats://%s:%s@%s:%d/",
		opts.Users[0].Username,
		opts.Users[0].Password,
		opts.Host, opts.Port)
	nc, err := nats.Connect(url, nats.NoReconnect())
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	ch := make(chan bool)
	msg := []byte("hello")
	sendFunc := func(toSend int) {
		defer func() {
			ch <- true
		}()
		for i := 0; i < toSend; i++ {
			if err := nc.Publish("foo", msg); err != nil {
				return
			}
		}
		nc.Flush()
	}
	go sendFunc(150)
	select {
	case <-time.After(time.Second):
	case <-ch:
		t.Fatalf("Rate should have been limited")
	}
	// Wait for publisher to finish
	nc.Close()
	<-ch
	// Shutdown server to restart with fresh stats
	srv.Shutdown()
	srv, _ = RunServerWithConfig("./configs/multi_user.conf")
	defer srv.Shutdown()

	// New connection
	nc, err = nats.Connect(url, nats.NoReconnect())
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	// Send more than rate but in more than 1 second. Rate should not be limited.
	start := time.Now()
	go sendFunc(60)
	<-ch
	dur := time.Now().Sub(start)
	if dur < time.Second {
		time.Sleep(time.Second - dur + 100*time.Millisecond)
		go sendFunc(60)
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("Rate should not have been limited")
		}
	}

	// Shutdown server to restart with fresh stats
	srv.Shutdown()
	srv, _ = RunServerWithConfig("./configs/multi_user.conf")
	defer srv.Shutdown()

	// New connection
	nc, err = nats.Connect(url, nats.NoReconnect())
	if err != nil {
		t.Fatalf("Expected a successful connect, got %v\n", err)
	}
	defer nc.Close()

	// Create a sub and qsub
	ch = make(chan bool, 2)
	recv := int32(0)
	toSend := int32(50)
	cb := func(_ *nats.Msg) {
		if atomic.AddInt32(&recv, 1) == 2*toSend {
			ch <- true
		}
	}
	sub1, err := nc.Subscribe("foo", cb)
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	sub2, err := nc.QueueSubscribe("foo", "queue", cb)
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	go sendFunc(int(toSend))
	select {
	case <-time.After(time.Second):
	case <-ch:
		t.Fatalf("Rate should have been limited")
	}
	sub1.Unsubscribe()
	sub2.Unsubscribe()
	nc.Flush()

	// Cause rate control to kick-in again
	go sendFunc(200)
	// Wait for us to be in doRateControl
	buf := make([]byte, 10000)
	timeout := time.Now().Add(time.Second)
	inRateControl := false
	for time.Now().Before(timeout) {
		n := runtime.Stack(buf, true)
		if strings.Contains(string(buf[:n]), "doRateControl") {
			inRateControl = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !inRateControl {
		t.Fatalf("Should be in rate control")
	}
	// Shutdown the server and verify that we are not blocked for the whole second
	start = time.Now()
	srv.Shutdown()
	dur = time.Now().Sub(start)
	if dur > 700*time.Millisecond {
		t.Fatalf("Server took too long to shutdown: %v", dur)
	}
}
