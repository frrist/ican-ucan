package main

import (
	"fmt"
	"log"
	"net/url"

	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/types"
	"github.com/storacha/go-ucanto/client"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/core/invocation"
	"github.com/storacha/go-ucanto/core/receipt"
	"github.com/storacha/go-ucanto/core/result"
	"github.com/storacha/go-ucanto/core/result/failure"
	fdm "github.com/storacha/go-ucanto/core/result/failure/datamodel"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/transport/http"
	"github.com/storacha/go-ucanto/ucan"

	"github.com/ipfs/go-cid"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
)

type Client struct {
	ClientID principal.Signer
	ServerID ucan.Principal
	// Proof is a delegation allowing the client to invoke
	// blob/allocate and blob/accept on the server.
	Proof delegation.Proof

	// connection to the server
	conn client.Connection
}

func NewClient(
	clientID principal.Signer,
	proof delegation.Proof,
	serverID ucan.Principal,
	serverURL *url.URL,
) (*Client, error) {
	ch := http.NewHTTPChannel(serverURL)
	conn, err := client.NewConnection(serverID, ch)
	if err != nil {
		return nil, fmt.Errorf("setting up client connection to server: %w", err)
	}
	return &Client{
		ClientID: clientID,
		ServerID: serverID,
		Proof:    proof,
		conn:     conn,
	}, nil
}

func (c *Client) AllocateBlob(space did.DID, block *StorageBlob) (*blob.Address, error) {
	digest, err := block.Digest()
	if err != nil {
		return nil, err
	}
	log.Println("Allocating blob ", Format(digest.Bytes()))
	blockDigestBytes := digest.Bytes() // multihash encoded sha256 of the blobs data
	i, err := blob.Allocate.Invoke(
		c.ClientID,                // issuer.
		c.ServerID,                // audience.
		c.ServerID.DID().String(), // resource.
		blob.AllocateCaveats{
			Space: space, // location (bucket) to put the blob.
			Blob: blob.Blob{ // the very blob its blobby self.
				Digest: blockDigestBytes,
				Size:   block.Size, // how big the blob be.
			},
			Cause: cidlink.Link{ // TODO what is this for?
				Cid: cid.NewCidV1(cid.Raw, blockDigestBytes),
			},
		},
		delegation.WithProof(c.Proof), // proof the client has the capability to allocate this blob on the server.
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate blob allocate invocation: %w", err)
	}

	res, err := client.Execute([]invocation.Invocation{i}, c.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to send blob allocate invocation: %w", err)
	}
	reader, err := receipt.NewReceiptReaderFromTypes[blob.AllocateOk, fdm.FailureModel](blob.AllocateOkType(), fdm.FailureType(), types.Converters...)
	if err != nil {
		return nil, fmt.Errorf("generating receipt reader: %w", err)
	}
	rcptLink, ok := res.Get(i.Link())
	if !ok {
		return nil, fmt.Errorf("receipt link not found in response")
	}
	rcpt, err := reader.Read(rcptLink, res.Blocks())
	if err != nil {
		return nil, fmt.Errorf("reading receipt: %w", err)
	}
	alloc, err := result.Unwrap(result.MapError(rcpt.Out(), failure.FromFailureModel))
	if err != nil {
		return nil, fmt.Errorf("received error from server: %w", err)
	}
	// address returned by the server the client may upload the bespoken blob to.
	return alloc.Address, nil
}
