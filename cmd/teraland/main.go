package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/terara-a/Teraland/internal/provider"
)

func main() {
	issuer := flag.String("issuer", "http://localhost:8080", "Public issuer URL (HTTPS outside development)")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address; use a TLS reverse proxy for public access")
	data := flag.String("data-dir", ".local/teraland", "Persistent private key directory")
	dev := flag.Bool("dev", false, "Allow HTTP and private-network federation fetches for local tests only")
	anchor := flag.String("trust-anchor", "", "Trusted federation entity identifier")
	jwks := flag.String("trust-anchor-jwks", "", "Path to pinned public trust anchor JWKS")
	flag.Parse()
	anchors := map[string]jose.JSONWebKeySet{}
	hints := []string{}
	if (*anchor == "") != (*jwks == "") {
		log.Fatal("provide both -trust-anchor and -trust-anchor-jwks")
	}
	if *anchor != "" {
		b, e := os.ReadFile(*jwks)
		if e != nil {
			log.Fatal(e)
		}
		var keys jose.JSONWebKeySet
		if e = json.Unmarshal(b, &keys); e != nil {
			log.Fatal(e)
		}
		if len(keys.Keys) == 0 {
			log.Fatal("empty trust anchor JWKS")
		}
		for _, k := range keys.Keys {
			if !k.Valid() || !k.IsPublic() {
				log.Fatal("trust anchor JWKS must contain valid public keys only")
			}
		}
		anchors[*anchor] = keys
		hints = append(hints, *anchor)
	}
	p, e := provider.New(provider.Config{Issuer: *issuer, DataDir: *data, Development: *dev, TrustAnchors: anchors, AuthorityHints: hints, Username: os.Getenv("TERALAND_USERNAME"), Password: os.Getenv("TERALAND_PASSWORD")})
	if e != nil {
		log.Fatal(e)
	}
	server := &http.Server{Addr: *listen, Handler: p.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("Teraland listening on %s (issuer %s)", *listen, *issuer)
	if len(anchors) == 0 {
		log.Print("No trust anchors configured; federated registration is disabled")
	}
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		log.Fatal(e)
	}
	if e = serve(ctx, server, listener); e != nil {
		log.Fatal(e)
	}
}

// serve waits until active handlers finish (or the shutdown deadline expires)
// before allowing main to exit.
func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		err := <-result
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
