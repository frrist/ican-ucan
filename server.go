package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-ucanto/core/invocation"
	"github.com/storacha/go-ucanto/core/receipt/fx"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/server"
	ucanhttp "github.com/storacha/go-ucanto/transport/http"
	"github.com/storacha/go-ucanto/ucan"
)

func ListenAndServe(addr string, serverID principal.Signer) error {
	srvMux, err := NewServer(serverID)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: srvMux,
	}
	log.Printf("Listening on %s\n", addr)
	err = srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type Server struct {
	ServerID   principal.Signer
	UCANServer server.ServerView
}

func NewServer(serverID principal.Signer) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", NewRootHandler(serverID))

	httpUCANServer, err := NewUCANServer(serverID)
	if err != nil {
		return nil, fmt.Errorf("creating UCAN server: %w", err)
	}
	svr := &Server{
		ServerID:   serverID,
		UCANServer: httpUCANServer,
	}
	svr.Serve(mux)

	return mux, nil
}

func (srv *Server) Serve(mux *http.ServeMux) {
	mux.Handle("POST /", NewUCANHandler(srv.UCANServer))
}

func NewRootHandler(id principal.Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("simple storage\n")))
		w.Write([]byte("- https://github.com/frrist/ican-ucan\n"))
		w.Write([]byte(fmt.Sprintf("- %s", id.DID())))
	})
}

func NewUCANHandler(ucanServer server.ServerView) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) error {
		res, err := ucanServer.Request(ucanhttp.NewHTTPRequest(r.Body, r.Header))
		if err != nil {
			return NewHTTPError(err, http.StatusInternalServerError)
		}

		for key, vals := range res.Headers() {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}

		if res.Status() != 0 {
			w.WriteHeader(res.Status())
		}

		_, err = io.Copy(w, res.Body())
		if err != nil {
			return fmt.Errorf("sending UCAN response: %w", err)
		}

		return nil
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := handler(writer, request); err != nil {
			log.Printf("ERROR: %s", err)
		}
	})
}

func NewUCANServer(serverID principal.Signer) (server.ServerView, error) {
	var options []server.Option
	options = append(options, MakeBlobAllocateHandler())
	return server.NewServer(serverID, options...)
}

func MakeBlobAllocateHandler() server.Option {
	return server.WithServiceMethod(
		blob.AllocateAbility,
		server.Provide(
			blob.Allocate,
			func(
				cap ucan.Capability[blob.AllocateCaveats],
				inv invocation.Invocation,
				iCtx server.InvocationContext,
			) (blob.AllocateOk, fx.Effects, error) {
				digest := cap.Nb().Blob.Digest
				log.Println("blob ", Format(digest))
				log.Printf("%s space: %s\n", blob.AllocateAbility, cap.Nb().Space)

				// only service principal can perform an allocation
				if cap.With() != iCtx.ID().DID().String() {
					return blob.AllocateOk{}, nil, fmt.Errorf(`%s does not have a "%s" capability provider`, cap.With(), cap.Can())
				}

				addr, err := url.Parse("http://localhost:8080")
				if err != nil {
					return blob.AllocateOk{}, nil, fmt.Errorf("the developer of this server really shit the bed, sorry: %w", err)
				}
				address := &blob.Address{
					URL:     *addr,
					Headers: http.Header{},
					Expires: uint64(time.Now().Add(time.Hour).Unix()),
				}
				return blob.AllocateOk{Size: cap.Nb().Blob.Size, Address: address}, nil, nil
			},
		),
	)
}

func Format(digest multihash.Multihash) string {
	key, _ := multibase.Encode(multibase.Base58BTC, digest)
	return key
}

type HTTPError struct {
	err        error
	statusCode int
}

// Error implements the error interface
func (he HTTPError) Error() string {
	return he.err.Error()
}

// StatusCode returns the HTTP status code associated with the error
func (he HTTPError) StatusCode() int {
	return he.statusCode
}

// NewHTTPError creates a new HTTPError
func NewHTTPError(err error, statusCode int) HTTPError {
	return HTTPError{err: err, statusCode: statusCode}
}
