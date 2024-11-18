// internal/graphql/resolvers/resolver.go

package resolvers

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vasuahex/go-lang/internal/graph/models" // This will contain your GraphQL generated types
	"github.com/vasuahex/go-lang/internal/models"
	"github.com/vasuahex/go-lang/internal/services"
)

// Resolver struct holds dependencies
type Resolver struct {
	AuthService *services.AuthService
}

// Query resolvers

func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

func (r *queryResolver) Me(ctx context.Context) (*model.User, error) {
	// Get user ID from context (assuming you've set it in authentication middleware)
	userID, ok := ctx.Value("userID").(string)
	if !ok {
		return nil, errors.New("unauthorized")
	}

	user, err := r.AuthService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Convert internal user model to GraphQL user model
	return &model.User{
		ID:           user.ID.Hex(),
		Name:         user.Name,
		Email:        user.Email,
		MobileNumber: &user.MobileNumber,
		Gender:       &user.Gender,
		DateOfBirth:  &user.DateOfBirth,
		Image:        &user.Image,
		IsVerified:   user.IsVerified,
		IsAdmin:      user.IsAdmin,
		Cart:         convertObjectIDsToStrings(user.Cart),
		Addresses:    convertObjectIDsToStrings(user.Addresses),
		IsBlocked:    user.IsBlocked,
	}, nil
}

func (r *queryResolver) Users(ctx context.Context) ([]*model.User, error) {
	// Check if user is admin
	userID, ok := ctx.Value("userID").(string)
	if !ok {
		return nil, errors.New("unauthorized")
	}

	isAdmin, err := r.AuthService.IsUserAdmin(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !isAdmin {
		return nil, errors.New("forbidden: admin access required")
	}

	users, err := r.AuthService.GetAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	// Convert internal users to GraphQL users
	var result []*model.User
	for _, user := range users {
		result = append(result, &model.User{
			ID:           user.ID.Hex(),
			Name:         user.Name,
			Email:        user.Email,
			MobileNumber: &user.MobileNumber,
			Gender:       &user.Gender,
			DateOfBirth:  &user.DateOfBirth,
			Image:        &user.Image,
			IsVerified:   user.IsVerified,
			IsAdmin:      user.IsAdmin,
			Cart:         convertObjectIDsToStrings(user.Cart),
			Addresses:    convertObjectIDsToStrings(user.Addresses),
			IsBlocked:    user.IsBlocked,
		})
	}

	return result, nil
}

// Mutation resolvers

func (r *Resolver) Mutation() MutationResolver {
	return &mutationResolver{r}
}

type mutationResolver struct{ *Resolver }

func (r *mutationResolver) Register(ctx context.Context, input model.RegisterInput) (*model.AuthResponse, error) {
	user, token, err := r.AuthService.RegisterUser(ctx, &models.RegisterInput{
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		return &model.AuthResponse{
			Message: err.Error(),
			Token:   nil,
			User:    nil,
		}, nil
	}

	// Convert user to GraphQL type
	graphqlUser := &model.User{
		ID:           user.ID.Hex(),
		Name:         user.Name,
		Email:        user.Email,
		MobileNumber: &user.MobileNumber,
		Gender:       &user.Gender,
		DateOfBirth:  &user.DateOfBirth,
		Image:        &user.Image,
		IsVerified:   user.IsVerified,
		IsAdmin:      user.IsAdmin,
		Cart:         convertObjectIDsToStrings(user.Cart),
		Addresses:    convertObjectIDsToStrings(user.Addresses),
		IsBlocked:    user.IsBlocked,
	}

	return &model.AuthResponse{
		Message: "Registration successful. Please verify your email.",
		Token:   &token,
		User:    graphqlUser,
	}, nil
}

func (r *mutationResolver) Login(ctx context.Context, input model.LoginInput) (*model.AuthResponse, error) {
	user, token, err := r.AuthService.LoginUser(ctx, &models.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		return &model.AuthResponse{
			Message: err.Error(),
			Token:   nil,
			User:    nil,
		}, nil
	}

	if user.IsBlocked {
		return &model.AuthResponse{
			Message: "Your account has been blocked. Please contact support.",
			Token:   nil,
			User:    nil,
		}, nil
	}

	// Convert user to GraphQL type
	graphqlUser := &model.User{
		ID:           user.ID.Hex(),
		Name:         user.Name,
		Email:        user.Email,
		MobileNumber: &user.MobileNumber,
		Gender:       &user.Gender,
		DateOfBirth:  &user.DateOfBirth,
		Image:        &user.Image,
		IsVerified:   user.IsVerified,
		IsAdmin:      user.IsAdmin,
		Cart:         convertObjectIDsToStrings(user.Cart),
		Addresses:    convertObjectIDsToStrings(user.Addresses),
		IsBlocked:    user.IsBlocked,
	}

	return &model.AuthResponse{
		Message: "Login successful",
		Token:   &token,
		User:    graphqlUser,
	}, nil
}

func (r *mutationResolver) VerifyEmail(ctx context.Context, token string) (*model.AuthResponse, error) {
	user, err := r.AuthService.VerifyEmail(ctx, token)
	if err != nil {
		return &model.AuthResponse{
			Message: err.Error(),
			Token:   nil,
			User:    nil,
		}, nil
	}

	// Convert user to GraphQL type
	graphqlUser := &model.User{
		ID:           user.ID.Hex(),
		Name:         user.Name,
		Email:        user.Email,
		MobileNumber: &user.MobileNumber,
		Gender:       &user.Gender,
		DateOfBirth:  &user.DateOfBirth,
		Image:        &user.Image,
		IsVerified:   user.IsVerified,
		IsAdmin:      user.IsAdmin,
		Cart:         convertObjectIDsToStrings(user.Cart),
		Addresses:    convertObjectIDsToStrings(user.Addresses),
		IsBlocked:    user.IsBlocked,
	}

	return &model.AuthResponse{
		Message: "Email verified successfully",
		User:    graphqlUser,
	}, nil
}

// Helper functions

func convertObjectIDsToStrings(ids []primitive.ObjectID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = id.Hex()
	}
	return result
}
