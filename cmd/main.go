package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
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

// ErrorResponse represents a standardized error response structure
type ErrorResponse struct {
	Errors []ErrorDetail `json:"errors"`
}

type ErrorDetail struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// sendJSONError is a helper function to send consistent JSON error responses
func sendJSONError(w http.ResponseWriter, status int, message string, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := ErrorResponse{
		Errors: []ErrorDetail{
			{
				Message: message,
				Code:    code,
			},
		},
	}
	json.NewEncoder(w).Encode(response)
}

// AuthMiddleware handles JWT authentication
func AuthMiddleware(next http.Handler, jwtSecret string, authService *services.AuthService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Disable caching for all GraphQL responses
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Skip auth for OPTIONS requests (CORS preflight)
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if the request is a GraphQL operation
		if r.URL.Path == "/query" && r.Method == "POST" {
			bodyBytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				sendJSONError(w, http.StatusBadRequest, "Error reading request body", "INVALID_REQUEST")
				return
			}

			bodyReader := bytes.NewReader(bodyBytes)
			var body struct {
				OperationName *string `json:"operationName"`
				Query         string  `json:"query"`
			}

			if err := json.NewDecoder(bodyReader).Decode(&body); err != nil {
				sendJSONError(w, http.StatusBadRequest, "Invalid JSON in request body", "INVALID_JSON")
				return
			}

			r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

			// Check if this is a public operation
			queryLower := strings.ToLower(body.Query)
			if strings.Contains(queryLower, "mutation register") ||
				strings.Contains(queryLower, "mutation login") ||
				strings.Contains(queryLower, "mutation verifyemail") {
				next.ServeHTTP(w, r)
				return
			}
		}

		// For protected routes, require authentication
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendJSONError(w, http.StatusUnauthorized, "Authorization header is required", "UNAUTHORIZED")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			sendJSONError(w, http.StatusUnauthorized, "Invalid authorization header format", "INVALID_AUTH_FORMAT")
			return
		}
		tokenStr := bearerToken[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			sendJSONError(w, http.StatusUnauthorized, "Invalid token", "INVALID_TOKEN")
			return
		}

		if !token.Valid {
			sendJSONError(w, http.StatusUnauthorized, "Invalid token", "INVALID_TOKEN")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			sendJSONError(w, http.StatusUnauthorized, "Invalid token claims", "INVALID_CLAIMS")
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			sendJSONError(w, http.StatusUnauthorized, "Invalid user ID in token", "INVALID_USER_ID")
			return
		}

		// Check token expiration
		exp, ok := claims["exp"].(float64)
		if !ok || time.Now().Unix() > int64(exp) {
			sendJSONError(w, http.StatusUnauthorized, "Token has expired", "TOKEN_EXPIRED")
			return
		}

		// Verify session token in database
		ctx := r.Context()
		isValidSession, err := authService.VerifySession(ctx, userID, tokenStr)
		if err != nil || !isValidSession {
			sendJSONError(w, http.StatusUnauthorized, "Invalid or expired session", "INVALID_SESSION")
			return
		}

		// Get user from database
		user, err := authService.GetUserByID(ctx, userID)
		if err != nil {
			sendJSONError(w, http.StatusUnauthorized, "User not found", "USER_NOT_FOUND")
			return
		}

		if user.IsBlocked {
			sendJSONError(w, http.StatusForbidden, "User is blocked", "USER_BLOCKED")
			return
		}

		// Create new context with user information
		ctx = context.WithValue(ctx, "userID", userID)
		ctx = context.WithValue(ctx, "isAdmin", user.IsAdmin)
		ctx = context.WithValue(ctx, "user", user)

		// Update request with new context
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

	// Create GraphQL server with custom error handling and no caching
	srv := handler.NewDefaultServer(schema.NewExecutableSchema(schema.Config{
		Resolvers: resolver,
	}))

	// Disable internal caching
	srv.Use(extension.FixedComplexityLimit(1000))

	// Configure custom error presentation
	srv.SetErrorPresenter(func(ctx context.Context, e error) *gqlerror.Error {
		err := graphql.DefaultErrorPresenter(ctx, e)
		log.Printf("GraphQL Error: %v", e)

		if strings.Contains(err.Message, "unauthorized") {
			return &gqlerror.Error{
				Message: err.Message,
				Extensions: map[string]interface{}{
					"code": "UNAUTHORIZED",
				},
			}
		}

		return &gqlerror.Error{
			Message: err.Message,
			Extensions: map[string]interface{}{
				"code": "INTERNAL_SERVER_ERROR",
			},
		}
	})

	// Setup router
	mux := http.NewServeMux()

	// Setup GraphQL endpoint with middleware
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corsHandler := CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				AuthMiddleware(srv, jwtSecret, authService).ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		}))

		corsHandler.ServeHTTP(w, r)
	})

	// Register the GraphQL endpoint
	mux.Handle("/query", wrappedHandler)

	// Setup the playground - note that it's at the root path "/"
	playgroundHandler := playground.Handler("GraphQL Playground", "/query")
	mux.Handle("/", CORSMiddleware(LoggingMiddleware(playgroundHandler)))

	// Configure the HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	log.Printf("GraphQL playground is now running on http://localhost:%s", port)
	log.Printf("GraphQL endpoint is running on http://localhost:%s/query", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
