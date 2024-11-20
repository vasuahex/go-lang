package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/vektah/gqlparser/v2/gqlerror"
	// "github.com/golang-jwt/jwt"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc"

	"github.com/vasuahex/go-lang/internal/config"
	"github.com/vasuahex/go-lang/internal/graph/schema"
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

	// Initialize auth service with revoked tokens collection
	authService := services.NewAuthService(db, emailService, cfg.JWTSecret)

	// Create index for revoked tokens collection
	revokedTokensCollection := db.Collection("revoked_tokens")
	indexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "token", Value: 1},      // Index on token field
			{Key: "revoked_at", Value: 1}, // Index on revocation timestamp
		},
		Options: options.Index().SetUnique(true),
	}

	if _, err := revokedTokensCollection.Indexes().CreateOne(ctx, indexModel); err != nil {
		log.Printf("Warning: Failed to create index on revoked_tokens: %v", err)
	}

	// Optional: Create TTL index to automatically delete expired tokens
	ttlIndexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "revoked_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(24 * 60 * 60)), // 24 hours
	}

	if _, err := revokedTokensCollection.Indexes().CreateOne(ctx, ttlIndexModel); err != nil {
		log.Printf("Warning: Failed to create TTL index on revoked_tokens: %v", err)
	}

	// Start gRPC server
	go runGRPCServer(cfg.GRPCPort, authService)

	// Start GraphQL server with middleware
	go runGraphQLServer(cfg.HTTPPort, authService, cfg.JWTSecret)

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

// AuthMiddleware handles JWT authentication
func AuthMiddleware(next http.Handler, jwtSecret string, authService *services.AuthService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for OPTIONS requests (CORS preflight)
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Extract the token
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}
		tokenStr := bearerToken[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
		
		if err != nil {
			// Handle specific JWT validation errors
			if ve, ok := err.(*jwt.ValidationError); ok {
				switch {
				case ve.Errors&jwt.ValidationErrorExpired != 0:
					http.Error(w, "Token has expired", http.StatusUnauthorized)
				case ve.Errors&jwt.ValidationErrorSignatureInvalid != 0:
					http.Error(w, "Invalid token signature", http.StatusUnauthorized)
				default:
					http.Error(w, "Invalid token", http.StatusUnauthorized)
				}
				return
			}
			http.Error(w, "Failed to parse token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims and user information
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Extract user ID
		userID, ok := claims["user_id"].(string)
		if !ok {
			http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
			return
		}

		// Check token expiration
		exp, ok := claims["exp"].(float64)
		if !ok {
			http.Error(w, "Invalid token expiration", http.StatusUnauthorized)
			return
		}

		if time.Now().Unix() > int64(exp) {
			http.Error(w, "Token has expired", http.StatusUnauthorized)
			return
		}

		// Get user from database to verify if they're still valid
		ctx := r.Context()
		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Check if user is blocked
		if user.IsBlocked {
			http.Error(w, "User is blocked", http.StatusForbidden)
			return
		}

		// Optional: Check if token is in a blacklist or revoked
		// You might want to add a method to check if the token has been revoked in the database
		isRevoked, err := authService.IsTokenRevoked(ctx, tokenStr)
		if err != nil || isRevoked {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		// Create new context with user information
		ctx = context.WithValue(ctx, "userID", userID)
		ctx = context.WithValue(ctx, "isAdmin", user.IsAdmin)
		ctx = context.WithValue(ctx, "user", user)

		// Create new request with updated context
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles CORS
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Set content type for JSON responses
		w.Header().Set("Content-Type", "application/json")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs incoming requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		next.ServeHTTP(w, r)

		log.Printf(
			"%s %s %s",
			r.Method,
			r.RequestURI,
			time.Since(start),
		)
	})
}

func runGraphQLServer(port string, authService *services.AuthService, jwtSecret string) {
	// Initialize GraphQL resolver
	resolver := schema.NewResolver(authService)

	// Create GraphQL server with custom error handling
	srv := handler.NewDefaultServer(schema.NewExecutableSchema(schema.Config{
		Resolvers: resolver,
	}))

	// Configure error handling to ensure proper JSON response
	srv.SetErrorPresenter(func(ctx context.Context, e error) *gqlerror.Error {
		// Log the original error for server-side debugging
		log.Printf("GraphQL Error: %v", e)

		// Create a GraphQL error with a standard format
		return &gqlerror.Error{
			Message: "Internal server error",
			Extensions: map[string]interface{}{
				"code": "INTERNAL_SERVER_ERROR",
			},
		}
	})

	// Setup routes with middleware
	mux := http.NewServeMux()

	// Add GraphQL playground
	playgroundHandler := playground.Handler("GraphQL playground", "/query")
	mux.Handle("/", CORSMiddleware(LoggingMiddleware(playgroundHandler)))

	// Add GraphQL endpoint with all middleware
	graphqlHandler := CORSMiddleware(
		LoggingMiddleware(
			AuthMiddleware(srv, jwtSecret, authService),
		),
	)
	mux.Handle("/query", graphqlHandler)

	// Configure server with more robust error handling
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog:     log.New(os.Stderr, "HTTP Server Error: ", log.Ldate|log.Ltime|log.Lshortfile),
	}

	log.Printf("GraphQL server starting on http://localhost:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to serve GraphQL: %v", err)
	}
}
