package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeDrainsActiveRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "finished")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { finished <- serve(ctx, server, listener) }()
	response := make(chan error, 1)
	go func() {
		r, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			body, e := io.ReadAll(r.Body)
			r.Body.Close()
			err = e
			if string(body) != "finished" && err == nil {
				err = io.ErrUnexpectedEOF
			}
		}
		response <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-finished:
		close(release)
		t.Fatalf("shutdown returned before handler finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-response:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("response not drained")
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}
