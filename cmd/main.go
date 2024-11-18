// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"

	"github.com/vasuahex/go-lang/internal/config"
	"github.com/vasuahex/go-lang/internal/graph"
	"github.com/vasuahex/go-lang/internal/services"
	pb "github.com/vasuahex/go-lang/proto/auth"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to MongoDB
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.MongoURI))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer mongoClient.Disconnect(ctx)

	// Ping MongoDB to verify connection
	if err := mongoClient.Ping(ctx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}
	log.Println("Successfully connected to MongoDB")

	// Initialize database
	db := mongoClient.Database(cfg.DatabaseName)

	// Initialize services
	emailService := services.NewSMTPEmailService(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUsername,
		cfg.SMTPPassword,
		cfg.SMTPFrom,
	)

	authService := services.NewAuthService(db, emailService)

	// Start gRPC server
	go runGRPCServer(cfg.GRPCPort, authService)

	// Start GraphQL server
	go runGraphQLServer(cfg.HTTPPort, authService)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")
	cancel()

	log.Println("Server exited properly")
}

func runGRPCServer(port string, authService *services.AuthService) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen for gRPC: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, authService)

	log.Printf("gRPC server starting on port %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}

func runGraphQLServer(port string, authService *services.AuthService) {
	// Initialize GraphQL resolver
	resolver := &graph.Resolver{
		AuthService: authService,
	}

	// Create GraphQL server
	srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{
		Resolvers: resolver,
	}))

	// Setup routes
	mux := http.NewServeMux()

	// Add GraphQL playground
	mux.Handle("/", playground.Handler("GraphQL playground", "/query"))

	// Add GraphQL endpoint with authentication middleware
	mux.Handle("/query", graph.AuthMiddleware(srv))

	// Configure server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Printf("GraphQL server starting on http://localhost:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to serve GraphQL: %v", err)
	}
}
