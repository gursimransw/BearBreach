package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	modelOutput "github.com/gursimransw/BearBreach/services/trust-guard/internal/handlers/model_output"
	userInput "github.com/gursimransw/BearBreach/services/trust-guard/internal/handlers/user_input"
	"github.com/gursimransw/BearBreach/services/trust-guard/internal/loader"
)

func main() {

	cfg := loader.MustLoad()
	//Mustload function is a part of config package , this is responsible for loading the configuration variables into this code from the config.yaml file
	//present in - config/server/config.yaml

	// if err != nil {
	// 	log.Fatal(err)
	// }

	DetectionRules, err := loader.LoadDetectionRules(cfg.DetectionRuleLibrary)
	if err != nil {
		slog.Error("Failed to load Detection Rules from ", slog.String("path", cfg.DetectionRuleLibrary), slog.String("error", err.Error()))
		os.Exit(1)
	} else {
		slog.Info("Loaded detection rule library from ", slog.String("path", cfg.DetectionRuleLibrary))

	}
	//Loading detection rules library

	PolicyConfig, err := loader.LoadPolicyConfig(cfg.PolicyConfig)
	if err != nil {
		slog.Error("Failed to load policy configuration from ", slog.String("path", cfg.PolicyConfig), slog.String("error", err.Error()))
		os.Exit(1)

	} else {
		slog.Info("Loaded policy configuration from ", slog.String("path", cfg.PolicyConfig))
	}
	//Loading the policy configuration

	//Setup router

	router := http.NewServeMux()

	router.HandleFunc("POST /api/v1/analyze-input", userInput.HandleUserInput(DetectionRules, PolicyConfig).ServeHTTP)

	router.HandleFunc("POST /api/v1/analyze-output", modelOutput.HandleModelOutput(DetectionRules, PolicyConfig).ServeHTTP)
	//Done Channel

	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	//Setup Server

	server := http.Server{
		Addr:    cfg.HTTPServer.Addr,
		Handler: router,
	}

	slog.Info("Server Started", slog.String("address", cfg.HTTPServer.Addr), slog.String("environment", cfg.Env))

	go func() {

		err := server.ListenAndServe()
		if err == http.ErrServerClosed {
			slog.Info("Server stopped", slog.String("error", err.Error()))
		} else if err != nil {
			slog.Error("Failed to start the server", slog.String("error", err.Error()))
			os.Exit(1)
		}

	}()

	<-done

	slog.Info("Shutting down the server")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = server.Shutdown(ctx)

	if err != nil {
		slog.Error("Failed to shutdown server", slog.String("error", err.Error()))
	}

	slog.Info("Server shutdown gracefully !!!")

}
