package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/ucan"
)

func main() {
	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a channel to listen for OS interrupt signals (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Goroutine to listen for Ctrl+C and cancel the context
	go func() {
		<-sigChan
		fmt.Println("\nReceived termination signal. Shutting down...")
		cancel() // Cancel the context
	}()

	serverP, err := signer.Generate()
	if err != nil {
		panic(err)
	}

	go func() {
		if err := ListenAndServe("0.0.0.0:8080", serverP); err != nil {
			panic(err)
		}
	}()

	clientP, err := signer.Generate()
	if err != nil {
		panic(err)
	}

	serverUrl, err := url.Parse("http://0.0.0.0:8080")
	if err != nil {
		panic(err)
	}

	dlg, err := delegation.Delegate(
		serverP,
		clientP,
		[]ucan.Capability[ucan.NoCaveats]{
			ucan.NewCapability(blob.AllocateAbility, serverP.DID().String(), ucan.NoCaveats{}),
		},
	)
	client, err := NewClient(clientP, delegation.FromDelegation(dlg), serverP, serverUrl)
	if err != nil {
		panic(err)
	}
	spaceDid, err := signer.Generate()
	if err != nil {
		panic(err)
	}

	sb, err := NewStorageBlob(128)
	if err != nil {
		panic(err)
	}

	blobAddr, err := client.AllocateBlob(spaceDid.DID(), sb)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Blob address: %+v\n", blobAddr)

	<-ctx.Done()
}
