package main

import (
	"log"
	"net/http"
	"os"

	"github.com/kanshurichard/GoHomeEasy/internal/gohomeeasy"
)

func main() {
	cfg, err := gohomeeasy.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	handler := gohomeeasy.NewHandler(cfg, logger)

	logger.Printf(
		"starting GoHomeEasy on %s with default_format=%s storage=%s",
		cfg.ListenAddr,
		cfg.DefaultSubscriptionFormat,
		cfg.StoragePath,
	)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
