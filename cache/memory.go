// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Package cache provides a small in-memory implementation of authz.Cache.
// It suits single-instance deployments and tests; a shared store (Redis) is
// the host's choice for multi-instance deployments — the interface is
// deliberately narrow (Get/Set/Del over opaque bytes).
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

// Get returns the value if present and unexpired.
func (c *Memory) Get(_ context.Context, key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	if e.live && time.Now().After(e.exp) {
		delete(c.m, key)
		return nil, false
	}
	return e.val, true
}

// Set stores val. A ttl <= 0 stores a non-expiring entry.
func (c *Memory) Set(_ context.Context, key string, val []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := entry{val: val}
	if ttl > 0 {
		e.live = true
		e.exp = time.Now().Add(ttl)
	}
	c.m[key] = e
}

// Del removes key.
func (c *Memory) Del(_ context.Context, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}
