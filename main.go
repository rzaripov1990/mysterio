package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/proxy"
	"mysterio/internal/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	var tok *token.Tokenizer
	if len(cfg.MaskHMACKey) > 0 {
		tok = token.New(cfg.MaskHMACKey)
	}
	m, err := masker.New(cfg.Rules, tok)
	if err != nil {
		slog.Error("masker", "err", err)
		os.Exit(1)
	}
	h, err := proxy.NewHandler(cfg, m)
	if err != nil {
		slog.Error("handler", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("listening",
			"addr", cfg.ListenAddr,
			"loki_enabled", cfg.LokiEnabled,
			"elastic_enabled", cfg.ElasticEnabled,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "err", err)
		os.Exit(1)
	}
	slog.Info("shutdown complete")
}
