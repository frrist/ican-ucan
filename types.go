package main

import (
	"crypto/rand"
	"fmt"

	"github.com/storacha/go-ucanto/core/ipld/hash"
	"github.com/storacha/go-ucanto/core/ipld/hash/sha256"
)

type StorageBlob struct {
	// size of Data
	Size uint64
	// actual data
	Data []byte
}

func (s *StorageBlob) Digest() (hash.Digest, error) {
	return sha256.Hasher.Sum(s.Data)
}

func NewStorageBlob(size int) (*StorageBlob, error) {
	bytes := make([]byte, size)
	read, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	if read != size {
		return nil, fmt.Errorf("expected %d bytes read, got %d", size, read)
	}
	return &StorageBlob{
		Size: uint64(len(bytes)),
		Data: bytes,
	}, nil
}
