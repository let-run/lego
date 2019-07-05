package http01

import (
	"net"
	"net/http"
	"strings"

	"github.com/go-acme/lego/log"
)

// ProviderServer implements ChallengeProvider for `http-01` challenge
// It may be instantiated without using the NewProviderServer function if
// you want only to use the default values.
type ProviderServer struct {
	iface    string
	port     string
	done     chan bool
	listener net.Listener
	mux      *http.ServeMux
}

// NewProviderServer creates a new ProviderServer on the selected interface and port.
// Setting iface and / or port to an empty string will make the server fall back to
// the "any" interface and port 80 respectively.
func NewProviderServer(iface, port string) *ProviderServer {
	s := &ProviderServer{iface: iface, port: port, mux: http.NewServeMux()}

	var err error
	s.listener, err = net.Listen("tcp", s.GetAddress())
	if err != nil {
		log.Fatalf("could not start HTTP server for challenge -> %v", err)
	}

	s.done = make(chan bool)

	httpServer := &http.Server{Handler: s.mux}

	// Once httpServer is shut down
	// we don't want any lingering connections, so disable KeepAlives.
	httpServer.SetKeepAlivesEnabled(false)

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")
		_, err := w.Write([]byte("OK"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	go func() {
		err = httpServer.Serve(s.listener)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Println(err)
		}
		s.done <- true
	}()

	return s
}

// Present starts a web server and makes the token available at `ChallengePath(token)` for web requests.
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	if s.port == "" {
		s.port = "80"
	}

	go s.serve(domain, token, keyAuth)
	return nil
}

func (s *ProviderServer) GetAddress() string {
	return net.JoinHostPort(s.iface, s.port)
}

// CleanUp closes the HTTP server and removes the token from `ChallengePath(token)`
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	if s.listener == nil {
		return nil
	}
	s.listener.Close()
	<-s.done
	return nil
}

func (s *ProviderServer) serve(domain, token, keyAuth string) {
	path := ChallengePath(token)

	// The handler validates the HOST header and request type.
	// For validation it then writes the token the server returned with the challenge

	s.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, domain) && r.Method == http.MethodGet {
			w.Header().Add("Content-Type", "text/plain")
			_, err := w.Write([]byte(keyAuth))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Infof("[%s] Served key authentication", domain)
		} else {
			log.Warnf("Received request for domain %s with method %s but the domain did not match any challenge. Please ensure your are passing the HOST header properly.", r.Host, r.Method)
			_, err := w.Write([]byte("TEST"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	})
}
