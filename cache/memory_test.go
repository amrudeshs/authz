// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/amrudeshs/authz"
)

func TestMemoryGetSetTTLDel(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()

	if _, ok := c.Get(ctx, "missing"); ok {
		t.Fatal("missing key must miss")
	}
	c.Set(ctx, "k", []byte("v"), time.Minute)
	if v, ok := c.Get(ctx, "k"); !ok || string(v) != "v" {
		t.Fatalf("got %q, %v", v, ok)
	}
	c.Del(ctx, "k")
	if _, ok := c.Get(ctx, "k"); ok {
		t.Fatal("deleted key must miss")
	}
}

func TestMemoryTTLExpiry(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	c.Set(ctx, "t", []byte("v"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get(ctx, "t"); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestMemoryNoTTLNeverExpires(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	c.Set(ctx, "forever", []byte("v"), 0)
	time.Sleep(2 * time.Millisecond)
	if _, ok := c.Get(ctx, "forever"); !ok {
		t.Fatal("ttl<=0 must not expire")
	}
}

func TestMemorySatisfiesAuthzCache(t *testing.T) {
	var _ authz.Cache = NewMemory()
}
