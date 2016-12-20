// Copyright 2015-2016 Apcera Inc. All rights reserved.

package server

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/go-nats"
)

var DefaultOptions = Options{
	Host:     "localhost",
	Port:     11222,
	HTTPPort: 11333,
	Cluster:  ClusterOpts{Port: 11444},
	ProfPort: 11280,
	NoLog:    true,
	NoSigs:   true,
}

// New Go Routine based server
func RunServer(opts *Options) *Server {
	if opts == nil {
		opts = &DefaultOptions
	}
	s := New(opts)
	if s == nil {
		panic("No NATS Server object returned.")
	}

	// Run server in Go routine.
	go s.Start()

	// Wait for accept loop(s) to be started
	if !s.ReadyForConnections(10 * time.Second) {
		panic("Unable to start NATS Server in Go Routine")
	}
	return s
}

func TestStartupAndShutdown(t *testing.T) {
	s := RunServer(&DefaultOptions)
	defer s.Shutdown()

	if !s.isRunning() {
		t.Fatal("Could not run server")
	}

	// Debug stuff.
	numRoutes := s.NumRoutes()
	if numRoutes != 0 {
		t.Fatalf("Expected numRoutes to be 0 vs %d\n", numRoutes)
	}

	numRemotes := s.NumRemotes()
	if numRemotes != 0 {
		t.Fatalf("Expected numRemotes to be 0 vs %d\n", numRemotes)
	}

	numClients := s.NumClients()
	if numClients != 0 && numClients != 1 {
		t.Fatalf("Expected numClients to be 1 or 0 vs %d\n", numClients)
	}

	numSubscriptions := s.NumSubscriptions()
	if numSubscriptions != 0 {
		t.Fatalf("Expected numSubscriptions to be 0 vs %d\n", numSubscriptions)
	}
}

func TestTlsCipher(t *testing.T) {
	if strings.Compare(tlsCipher(0x0005), "TLS_RSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x000a), "TLS_RSA_WITH_3DES_EDE_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x002f), "TLS_RSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x0035), "TLS_RSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc007), "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc009), "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc00a), "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc011), "TLS_ECDHE_RSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc012), "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc013), "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc014), "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("IUnknownnvalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02f), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02b), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc030), "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02c), "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if !strings.Contains(tlsCipher(0x9999), "Unknown") {
		t.Fatalf("Expected an unknown cipher.")
	}
}

func TestGetConnectURLs(t *testing.T) {
	opts := DefaultOptions
	opts.Port = 4222

	var globalIP net.IP

	checkGlobalConnectURLs := func() {
		s := New(&opts)
		defer s.Shutdown()

		urls := s.getClientConnectURLs()
		if len(urls) == 0 {
			t.Fatalf("Expected to get a list of urls, got none for listen addr: %v", opts.Host)
		}
		for _, u := range urls {
			tcpaddr, err := net.ResolveTCPAddr("tcp", u)
			if err != nil {
				t.Fatalf("Error resolving: %v", err)
			}
			ip := tcpaddr.IP
			if !ip.IsGlobalUnicast() {
				t.Fatalf("IP %v is not global", ip.String())
			}
			if ip.IsUnspecified() {
				t.Fatalf("IP %v is unspecified", ip.String())
			}
			addr := strings.TrimSuffix(u, ":4222")
			if addr == opts.Host {
				t.Fatalf("Returned url is not right: %v", u)
			}
			if globalIP == nil {
				globalIP = ip
			}
		}
	}

	listenAddrs := []string{"0.0.0.0", "::"}
	for _, listenAddr := range listenAddrs {
		opts.Host = listenAddr
		checkGlobalConnectURLs()
	}

	checkConnectURLsHasOnlyOne := func() {
		s := New(&opts)
		defer s.Shutdown()

		urls := s.getClientConnectURLs()
		if len(urls) != 1 {
			t.Fatalf("Expected one URL, got %v", urls)
		}
		tcpaddr, err := net.ResolveTCPAddr("tcp", urls[0])
		if err != nil {
			t.Fatalf("Error resolving: %v", err)
		}
		ip := tcpaddr.IP
		if ip.String() != opts.Host {
			t.Fatalf("Expected connect URL to be %v, got %v", opts.Host, ip.String())
		}
	}

	singleConnectReturned := []string{"127.0.0.1", "::1"}
	if globalIP != nil {
		singleConnectReturned = append(singleConnectReturned, globalIP.String())
	}
	for _, listenAddr := range singleConnectReturned {
		opts.Host = listenAddr
		checkConnectURLsHasOnlyOne()
	}
}

func TestNoDeadlockOnStartFailure(t *testing.T) {
	opts := DefaultOptions
	opts.Host = "x.x.x.x" // bad host
	opts.Port = 4222
	opts.Cluster.Host = "localhost"
	opts.Cluster.Port = 6222

	s := New(&opts)
	// This should return since it should fail to start a listener
	// on x.x.x.x:4222
	s.Start()
	// We should be able to shutdown
	s.Shutdown()
}

func TestMaxConnections(t *testing.T) {
	opts := DefaultOptions
	opts.MaxConn = 1
	s := RunServer(&opts)
	defer s.Shutdown()

	addr := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	nc, err := nats.Connect(addr)
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer nc.Close()

	nc2, err := nats.Connect(addr)
	if err == nil {
		nc2.Close()
		t.Fatal("Expected connection to fail")
	}
}

func TestProcessCommandLineArgs(t *testing.T) {
	var host string
	var port int
	cmd := flag.NewFlagSet("gnatsd", flag.ExitOnError)
	cmd.StringVar(&host, "a", "0.0.0.0", "Host.")
	cmd.IntVar(&port, "p", 4222, "Port.")

	cmd.Parse([]string{"-a", "127.0.0.1", "-p", "9090"})
	showVersion, showHelp, err := ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if showVersion || showHelp {
		t.Errorf("Expected not having to handle subcommands")
	}

	cmd.Parse([]string{"version"})
	showVersion, showHelp, err = ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if !showVersion {
		t.Errorf("Expected having to handle version command")
	}
	if showHelp {
		t.Errorf("Expected not having to handle help command")
	}

	cmd.Parse([]string{"help"})
	showVersion, showHelp, err = ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if showVersion {
		t.Errorf("Expected not having to handle version command")
	}
	if !showHelp {
		t.Errorf("Expected having to handle help command")
	}

	cmd.Parse([]string{"foo", "-p", "9090"})
	_, _, err = ProcessCommandLineArgs(cmd)
	if err == nil {
		t.Errorf("Expected an error handling the command arguments")
	}
}

func TestRateLimiting(t *testing.T) {
	// Rate limited to 100 msgs/sec
	opts := DefaultOptions
	opts.MsgsRate = 300
	s := RunServer(&opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d",
		DefaultOptions.Host, DefaultOptions.Port),
		nats.NoReconnect())
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}

	msg := []byte("hello")
	toSend := int32(150)
	recv := int32(0)
	ch := make(chan struct{}, 1)
	cb := func(_ *nats.Msg) {
		if atomic.AddInt32(&recv, 1) == 2*atomic.LoadInt32(&toSend) {
			ch <- struct{}{}
		}
	}
	sub1, err := nc.Subscribe("foo", cb)
	if err != nil {
		t.Fatalf("Unexpected error on subscribe: %v", err)
	}
	sub2, err := nc.QueueSubscribe("foo", "queue", cb)
	if err != nil {
		t.Fatalf("Unexpected error on subscribe: %v", err)
	}
	nc.Flush()

	sendFunc := func(nc *nats.Conn, toSend int32) {
		for i := 0; i < int(toSend); i++ {
			if err := nc.Publish("foo", msg); err != nil {
				return
			}
		}
	}

	go sendFunc(nc, toSend)
	select {
	case <-time.After(time.Second):
	case <-ch:
		t.Fatal("Rate should have been limited")
	}
	start := time.Now()
	// We send/recv more than the rate allows, so wait for the
	// rest to arrive.
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed-out waiting for messages")
	}
	dur := time.Now().Sub(start)
	if dur < time.Second {
		time.Sleep(time.Second - dur + 150*time.Millisecond)
	}
	// Reset some vars and send some messages. The total since
	// last rate limit would make total > rate limit, but we
	// should not be limited since we waited more than a period.
	atomic.StoreInt32(&recv, 0)
	atomic.StoreInt32(&toSend, 60)
	go sendFunc(nc, toSend)
	select {
	case <-time.After(time.Second):
		t.Fatal("Rate should not have been limited")
	case <-ch:
	}
	sub1.Unsubscribe()
	sub2.Unsubscribe()
	nc.Flush()
	nc.Close()

	// Verify that if blocking in rate limit, shuting down the server
	// kick it out
	var ncs [6]*nats.Conn
	for i := 0; i < len(ncs); i++ {
		nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d",
			DefaultOptions.Host, DefaultOptions.Port),
			nats.NoReconnect())
		if err != nil {
			t.Fatalf("Error creating client: %v\n", err)
		}
		cnc := nc
		ncs[i] = cnc
		go sendFunc(cnc, 100)
	}
	// Wait a bit so that we know server is blocking
	time.Sleep(200 * time.Millisecond)
	start = time.Now()
	s.Shutdown()
	dur = time.Now().Sub(start)
	if dur > 200*time.Millisecond {
		t.Fatalf("Shutting down the server took too long: %v", dur)
	}
	for _, nc := range ncs {
		nc.Close()
	}
}
