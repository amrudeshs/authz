// Copyright 2026 The authz Authors.
// SPDX-License-Identifier: Apache-2.0

// Command example runs the multi-tenant Projects & Tasks showcase API. With
// DATABASE_URL set it uses Postgres (the compose topology); otherwise it
// serves the in-memory demo dataset so it can be run and tested with no
// external dependencies.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	addr := env("ADDR", ":8080")

	var store Store
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		pool, err := pgxpool.New(context.Background(), dsn)
		if err != nil {
			log.Fatalf("db: %v", err)
		}
		defer pool.Close()
		if err := pool.Ping(context.Background()); err != nil {
			log.Fatalf("db ping: %v", err)
		}
		store = &pgStore{pool: pool}
		log.Print("store: Postgres")
	} else {
		store = newMemStore()
		log.Print("store: in-memory demo dataset (set DATABASE_URL for Postgres)")
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(store).router(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
