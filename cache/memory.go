// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Package cache provides a small in-memory implementation of authz.Cache.
// It suits single-instance deployments and tests; a shared store (Redis) is
// the host's choice for multi-instance deployments. The interface is Get,
// Set, Del, and Flush over opaque bytes, and every mutation reports failure.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/amrudeshs/authz"
)

// Memory is a concurrency-safe, TTL-aware in-memory cache.
type Memory struct {
	mu sync.Mutex
	m  map[string]entry
}

type entry struct {
	val  []byte
	exp  time.Time
	live bool
}

// NewMemory returns an empty in-memory cache.
func NewMemory() *Memory { return &Memory{m: map[string]entry{}} }

var _ authz.Cache = (*Memory)(nil)

// Get returns a copy of the value if present and unexpired.
func (c *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false, nil
	}
	if e.live && time.Now().After(e.exp) {
		delete(c.m, key)
		return nil, false, nil
	}
	return copyBytes(e.val), true, nil
}

// Set stores a copy of val. A ttl <= 0 stores a non-expiring entry.
func (c *Memory) Set(_ context.Context, key string, val []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := entry{val: copyBytes(val)}
	if ttl > 0 {
		e.live = true
		e.exp = time.Now().Add(ttl)
	}
	c.m[key] = e
	return nil
}

// Del removes key.
func (c *Memory) Del(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
	return nil
}

// Flush drops every entry. Role-definition edits affect every holder; this
// is part of authz.Cache, not an optional extra.
func (c *Memory) Flush(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = map[string]entry{}
	return nil
}

func copyBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
