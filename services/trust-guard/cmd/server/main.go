package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gursimransw/BearBreach/services/trust-guard/internal/clients"
	modelOutput "github.com/gursimransw/BearBreach/services/trust-guard/internal/handlers/model_output"
	userInput "github.com/gursimransw/BearBreach/services/trust-guard/internal/handlers/user_input"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/loader"
)

func main() {

	/*
		Load server configuration, detection rules, and security policy.
		Startup fails if the rules or policy cannot be loaded.
	*/

	cfg := loader.MustLoad()

	DetectionRules, err := loader.LoadDetectionRules(cfg.DetectionRuleLibrary)
	if err != nil {
		slog.Error("Failed to load detection rules", slog.String("path", cfg.DetectionRuleLibrary), slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("Loaded detection rule library", slog.String("path", cfg.DetectionRuleLibrary))

	PolicyConfig, err := loader.LoadPolicyConfig(cfg.PolicyConfig)
	if err != nil {
		slog.Error("Failed to load policy configuration", slog.String("path", cfg.PolicyConfig), slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("Loaded policy configuration", slog.String("path", cfg.PolicyConfig))

	/*
		Create the Semantic Detector HTTP client only once.
		Both API handlers reuse it for requests to the Python service.

		The URL and timeout are initial development defaults. Move them
		into your existing server configuration before deployment.
	*/

	semanticClient, err := clients.NewSemanticDetectorClient(
		"http://bb-semantic-detector:8001",
		3*time.Second,
	)
	if err != nil {
		slog.Error("Failed to initialize semantic detector client", slog.String("error", err.Error()))
		os.Exit(1)
	}

	/*
		Register both analysis endpoints with the same loaded rules,
		policy configuration, and reusable Semantic Detector client.
	*/

	router := http.NewServeMux()

	router.HandleFunc(
		"POST /api/v1/analyze-input",
		userInput.HandleUserInput(DetectionRules, PolicyConfig, semanticClient).ServeHTTP,
	)

	router.HandleFunc(
		"POST /api/v1/analyze-output",
		modelOutput.HandleModelOutput(DetectionRules, PolicyConfig, semanticClient).ServeHTTP,
	)

	/*
		Listen for operating-system shutdown signals so the HTTP server
		can finish active requests before exiting.
	*/

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(done)

	server := http.Server{
		Addr:    cfg.HTTPServer.Addr,
		Handler: router,
	}

	slog.Info("Server started", slog.String("address", cfg.HTTPServer.Addr), slog.String("environment", cfg.Env))

	go func() {
		err := server.ListenAndServe()
		if err == http.ErrServerClosed {
			slog.Info("Server stopped")
		} else if err != nil {
			slog.Error("Failed to start the server", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	<-done

	/*
		Allow up to five seconds for the server to shut down gracefully.
	*/

	slog.Info("Shutting down the server")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Failed to shut down server", slog.String("error", err.Error()))
		return
	}

	slog.Info("Server shut down gracefully")
}
