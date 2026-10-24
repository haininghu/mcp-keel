// Command mcp-keel runs the policy-governed MCP server over stdio.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/server"
)

// version is injected at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mcp-keel:", err)
		os.Exit(1)
	}
}

func run() error {
	defaultConfig := "configs/config.yaml"
	if fromEnv := os.Getenv("MCP_KEEL_CONFIG"); fromEnv != "" {
		defaultConfig = fromEnv
	}
	configPath := flag.String("config", defaultConfig, "path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := newLogger(cfg.Server.LogLevel)

	registry, err := kube.NewRegistry(cfg, logger)
	if err != nil {
		return err
	}

	srv := server.New(cfg, server.KubeRegistry(registry), logger)

	logger.Info("starting mcp-keel",
		"version", version,
		"config", *configPath,
		"providers", len(cfg.Providers),
	)

	if err := srv.MCPServer(version).Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// newLogger builds a stderr text logger for the configured level. All logging
// goes to stderr because stdout carries the MCP stdio transport.
func newLogger(level config.LogLevel) *slog.Logger {
	var lvl slog.Level
	switch level {
	case config.LogLevelDebug:
		lvl = slog.LevelDebug
	case config.LogLevelWarn:
		lvl = slog.LevelWarn
	case config.LogLevelError:
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
