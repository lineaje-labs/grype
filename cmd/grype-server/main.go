package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/glebarez/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/commands/server"
)

const applicationName = "grype-server"

var (
	version        = "unset"
	buildDate      = "unset"
	gitCommit      = "unset"
	gitDescription = "unset"
)

func main() {
	var (
		addr            = flag.String("addr", ":8080", "listen address (host:port)")
		refreshInterval = flag.Duration("refresh-interval", 2*time.Hour, "how often to refresh the vulnerability DB in the background; 0 disables")
		shutdownSecs    = flag.Int("shutdown-timeout", 30, "graceful shutdown timeout in seconds")
		byCVE           = flag.Bool("by-cve", false, "orient results by CVE ID instead of the original advisory ID")
	)
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	id := clio.Identification{
		Name:           applicationName,
		Version:        version,
		BuildDate:      buildDate,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
	}

	cfg := server.DefaultConfig(id)
	cfg.Addr = *addr
	cfg.RefreshInterval = *refreshInterval
	cfg.ByCVE = *byCVE

	srv, err := server.New(cfg)
	if err != nil {
		slog.Error("failed to start server", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down…")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*shutdownSecs)*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}
