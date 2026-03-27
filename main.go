package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rahul-roy-glean/capsule-access-plane/accessplane"
	"github.com/rahul-roy-glean/capsule-access-plane/grants"
	"github.com/rahul-roy-glean/capsule-access-plane/identity"
	"github.com/rahul-roy-glean/capsule-access-plane/manifest"
	"github.com/rahul-roy-glean/capsule-access-plane/policy"
	"github.com/rahul-roy-glean/capsule-access-plane/providers"
	"github.com/rahul-roy-glean/capsule-access-plane/proxy"
	"github.com/rahul-roy-glean/capsule-access-plane/runtime"
	"github.com/rahul-roy-glean/capsule-access-plane/server"
	"github.com/rahul-roy-glean/capsule-access-plane/store"
)

func main() {
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	proxyAddr := os.Getenv("PROXY_ADDR")
	// PROXY_ADDR empty means no CONNECT proxy (backward compatible).
	proxyAllowPassthrough := os.Getenv("PROXY_ALLOW_PASSTHROUGH") == "true"

	// Read attestation secret (required)
	attestationSecret := os.Getenv("ATTESTATION_SECRET")
	if attestationSecret == "" {
		slog.Error("ATTESTATION_SECRET environment variable is required")
		os.Exit(1)
	}

	// Database URL (default: capsule-access.db)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "capsule-access.db"
	}

	// Create identity verifier
	verifier, err := identity.NewHMACVerifier([]byte(attestationSecret))
	if err != nil {
		slog.Error("failed to create HMAC verifier", "err", err)
		os.Exit(1)
	}

	// Open SQLite store and run migrations
	ctx := context.Background()
	dataStore, err := store.Open(ctx, databaseURL)
	if err != nil {
		slog.Error("failed to open store", "err", err)
		os.Exit(1)
	}
	defer func() { _ = dataStore.Close() }()
	slog.Info("opened SQLite store", "database", databaseURL)

	// Load manifests from embedded filesystem
	registry := manifest.NewInMemoryRegistry()
	loader := &manifest.YAMLLoader{}
	if err := manifest.LoadAllFamilies(loader, registry); err != nil {
		slog.Error("failed to load manifest families", "err", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer: acceptable in main()
	}
	slog.Info("loaded manifest families", "count", len(registry.List()))

	// Create policy engine
	engine := policy.NewManifestBasedEngine(registry)

	// Implementation availability
	implAvailability := map[accessplane.Lane]accessplane.ImplementationState{
		accessplane.LaneDirectHTTP:      accessplane.StateImplemented,
		accessplane.LaneHelperSession:   accessplane.StateImplementationDeferred,
		accessplane.LaneRemoteExecution: accessplane.StateImplemented,
	}

	// Create provider registry.
	logger := slog.Default()
	credResolver := grants.NewCredentialResolver(dataStore.DB())
	providerRegistry := providers.NewRegistry()

	// Load providers from config file if specified.
	if configPath := os.Getenv("PROVIDERS_CONFIG"); configPath != "" {
		n, err := providers.LoadFromFile(configPath, providerRegistry, credResolver)
		if err != nil {
			slog.Error("failed to load provider config", "path", configPath, "err", err)
			os.Exit(1)
		}
		slog.Info("loaded provider configs", "count", n, "path", configPath)
	}

	// Set up default static provider from CREDENTIAL_REF (backward compatible).
	credentialRef := os.Getenv("CREDENTIAL_REF")
	if credentialRef == "" {
		credentialRef = "env:GITHUB_TOKEN"
	}
	defaultProvider := providers.NewStaticProvider("default", credResolver, credentialRef, nil)
	providerRegistry.SetDefault(defaultProvider)
	// Only register if "default" wasn't already loaded from config.
	_ = providerRegistry.Register(defaultProvider)

	// Start all providers.
	for _, p := range providerRegistry.All() {
		if err := p.Start(ctx); err != nil {
			slog.Error("failed to start provider", "name", p.Name(), "err", err)
			os.Exit(1)
		}
	}

	// Create grant store and service
	grantStore := grants.NewSQLStore(dataStore.DB())
	grantService := grants.NewService(grantStore, 15*time.Minute)

	// Create direct HTTP proxy adapter
	adapter := runtime.NewDirectHTTPAdapter(registry)

	// Create handlers
	resolveHandler := server.NewResolveHandler(verifier, engine, implAvailability, logger)
	grantHandlers := server.NewGrantHandlers(verifier, grantService, adapter, providerRegistry, registry, logger)
	executeHandler := server.NewExecuteHandler(verifier, registry, engine, providerRegistry, logger)
	tokenHandlers := server.NewTokenHandlers(providerRegistry)
	phantomHandlers := server.NewPhantomHandlers(registry)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Wire resolve endpoint
	mux.Handle("POST /v1/resolve", resolveHandler)

	// Wire grant lifecycle endpoints
	mux.HandleFunc("POST /v1/grants/project", grantHandlers.ProjectGrant)
	mux.HandleFunc("POST /v1/grants/exchange", grantHandlers.ExchangeCapability)
	mux.HandleFunc("POST /v1/grants/refresh", grantHandlers.RefreshGrant)
	mux.HandleFunc("POST /v1/grants/revoke", grantHandlers.RevokeGrant)

	// Wire remote broker execution endpoint
	mux.Handle("POST /v1/execute/http", executeHandler)

	// Wire token update and phantom env endpoints
	mux.HandleFunc("POST /v1/providers/update-token", tokenHandlers.UpdateToken)
	mux.HandleFunc("GET /v1/phantom-env", phantomHandlers.GetPhantomEnv)

	// Remaining stubs
	mux.HandleFunc("POST /v1/events/runner", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":   "not_implemented",
			"message": "PublishRunnerEvent not yet implemented",
		})
	})

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start CONNECT proxy if PROXY_ADDR is set.
	if proxyAddr != "" {
		ca, err := proxy.NewCertAuthority()
		if err != nil {
			slog.Error("failed to create CA for proxy", "err", err)
			os.Exit(1)
		}
		connectProxy := &proxy.ConnectProxy{
			CA:                         ca,
			Manifests:                  registry,
			Providers:                  providerRegistry,
			Logger:                     logger,
			AllowNonProviderPassthrough: proxyAllowPassthrough,
		}

		// Expose the MITM CA cert so clients can trust the proxy.
		caPEM := ca.CACertPEM()
		mux.HandleFunc("GET /ca.pem", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(caPEM)
		})

		go func() {
			slog.Info("starting CONNECT proxy", "addr", proxyAddr)
			if err := connectProxy.ListenAndServe(proxyAddr); err != nil {
				slog.Error("CONNECT proxy error", "err", err)
			}
		}()
		defer func() { _ = connectProxy.Close() }()
	}

	go func() {
		slog.Info("starting access plane", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-shutdownCtx.Done()
	slog.Info("shutting down")

	gracefulCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(gracefulCtx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
