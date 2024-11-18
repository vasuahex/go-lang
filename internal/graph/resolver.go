package graph

import (
	pb "/GO-server/proto/auth"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Resolver serves as a dependency injection container for your GraphQL resolvers
type Resolver struct {
	AuthService *service.AuthService
}

// Mutation returns the resolver for mutation operations
type mutationResolver struct {
	*Resolver
}

// Query returns the resolver for query operations
type queryResolver struct {
	*Resolver
}

func (r *Resolver) Mutation() MutationResolver {
	return &mutationResolver{r}
}

func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

// Mutation Resolvers
func (r *mutationResolver) Register(ctx context.Context, input RegisterInput) (*AuthResponse, error) {
	// Convert GraphQL input to gRPC request
	req := &pb.RegisterRequest{
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
	}

	// Call the gRPC service
	resp, err := r.AuthService.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	// Convert gRPC response to GraphQL response
	return &AuthResponse{
		Message: resp.Message,
		Token:   resp.Token,
		User:    convertPbUserToGraphQL(resp.User),
	}, nil
}

func (r *mutationResolver) Login(ctx context.Context, input LoginInput) (*AuthResponse, error) {
	req := &pb.LoginRequest{
		Email:    input.Email,
		Password: input.Password,
	}

	resp, err := r.AuthService.Login(ctx, req)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Message: resp.Message,
		Token:   resp.Token,
		User:    convertPbUserToGraphQL(resp.User),
	}, nil
}

func (r *mutationResolver) VerifyEmail(ctx context.Context, token string) (*AuthResponse, error) {
	req := &pb.VerifyEmailRequest{
		Token: token,
	}

	resp, err := r.AuthService.VerifyEmail(ctx, req)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Message: resp.Message,
		Token:   resp.Token,
		User:    convertPbUserToGraphQL(resp.User),
	}, nil
}

// Query Resolvers
func (r *queryResolver) Me(ctx context.Context) (*User, error) {
	// Get user from context (requires auth middleware)
	userID := ctx.Value("userID")
	if userID == nil {
		return nil, fmt.Errorf("not authenticated")
	}

	// Get user from database
	user, err := r.AuthService.GetUserByID(ctx, userID.(string))
	if err != nil {
		return nil, err
	}

	return convertPbUserToGraphQL(user), nil
}

func (r *queryResolver) Users(ctx context.Context) ([]*User, error) {
	// Check if user is admin (requires auth middleware)
	isAdmin := ctx.Value("isAdmin")
	if isAdmin == nil || !isAdmin.(bool) {
		return nil, fmt.Errorf("unauthorized")
	}

	// Get users from database
	users, err := r.AuthService.GetUsers(ctx)
	if err != nil {
		return nil, err
	}

	// Convert to GraphQL type
	var result []*User
	for _, u := range users {
		result = append(result, convertPbUserToGraphQL(u))
	}

	return result, nil
}

// Helper functions to convert between protobuf and GraphQL types
func convertPbUserToGraphQL(pbUser *pb.User) *User {
	if pbUser == nil {
		return nil
	}

	return &User{
		ID:           pbUser.Id,
		Name:         pbUser.Name,
		Email:        pbUser.Email,
		MobileNumber: &pbUser.MobileNumber,
		Gender:       &pbUser.Gender,
		DateOfBirth:  &pbUser.DateOfBirth,
		Image:        &pbUser.Image,
		IsVerified:   pbUser.IsVerified,
		IsAdmin:      pbUser.IsAdmin,
		IsBlocked:    pbUser.IsBlocked,
		Cart:         pbUser.Cart,
		Addresses:    pbUser.Addresses,
	}
}

// Custom middleware for authentication
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token := r.Header.Get("Authorization")

		if token != "" {
			// Remove 'Bearer ' prefix if present
			token = strings.TrimPrefix(token, "Bearer ")

			// Verify token and get user claims
			userID, isAdmin, err := verifyToken(token)
			if err == nil {
				// Add user info to context
				ctx = context.WithValue(ctx, "userID", userID)
				ctx = context.WithValue(ctx, "isAdmin", isAdmin)
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Token verification helper
func verifyToken(token string) (string, bool, error) {
	// TODO: Implement JWT verification
	// This is a placeholder - implement your actual JWT verification logic
	return "", false, fmt.Errorf("not implemented")
}
