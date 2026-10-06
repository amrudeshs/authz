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

	if _, ok, err := c.Get(ctx, "missing"); err != nil || ok {
		t.Fatal("missing key must miss")
	}
	if err := c.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := c.Get(ctx, "k"); err != nil || !ok || string(v) != "v" {
		t.Fatalf("got %q, %v, %v", v, ok, err)
	}
	if err := c.Del(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.Get(ctx, "k"); err != nil || ok {
		t.Fatal("deleted key must miss")
	}
}

func TestMemoryTTLExpiry(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	if err := c.Set(ctx, "t", []byte("v"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "t"); err != nil || ok {
		t.Fatal("expired entry must miss")
	}
}

func TestMemoryNoTTLNeverExpires(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	if err := c.Set(ctx, "forever", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, ok, err := c.Get(ctx, "forever"); err != nil || !ok {
		t.Fatal("ttl<=0 must not expire")
	}
}

func TestMemoryFlush(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	if err := c.Set(ctx, "a", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "b", []byte("2"), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.Get(ctx, "a"); err != nil || ok {
		t.Fatal("flush must drop every entry")
	}
	if _, ok, err := c.Get(ctx, "b"); err != nil || ok {
		t.Fatal("flush must drop non-expiring entries too")
	}
}

func TestMemorySatisfiesAuthzCache(t *testing.T) {
	var _ authz.Cache = NewMemory()
}
