// internal/graph/schema/resolvers.go

package schema

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vasuahex/go-lang/internal/graph/models"
	"github.com/vasuahex/go-lang/internal/services"
	pb "github.com/vasuahex/go-lang/proto/auth"
)

// Resolver struct that holds your services
type Resolver struct {
	AuthService *services.AuthService
}

// NewResolver creates a new resolver instance
func NewResolver(authService *services.AuthService) *Resolver {
	return &Resolver{
		AuthService: authService,
	}
}

// Query resolvers
type queryResolver struct {
	*Resolver
}

func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

func (r *queryResolver) Me(ctx context.Context) (*models.User, error) {
	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user, err := r.AuthService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return convertProtoToGraphQLUser(user), nil
}

func (r *queryResolver) Users(ctx context.Context) ([]*models.User, error) {
	if !isAdmin(ctx) {
		return nil, errors.New("unauthorized: admin access required")
	}

	users, err := r.AuthService.GetUsers(ctx)
	if err != nil {
		return nil, err
	}

	return convertProtoToGraphQLUsers(users), nil
}

// Mutation resolvers
type mutationResolver struct {
	*Resolver
}

func (r *Resolver) Mutation() MutationResolver {
	return &mutationResolver{r}
}

func (r *mutationResolver) Register(ctx context.Context, input models.RegisterInput) (*models.AuthResponse, error) {
	req := &pb.RegisterRequest{
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
	}

	resp, err := r.AuthService.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	return convertProtoToGraphQLAuthResponse(resp), nil
}

func (r *mutationResolver) Login(ctx context.Context, input models.LoginInput) (*models.AuthResponse, error) {
	req := &pb.LoginRequest{
		Email:    input.Email,
		Password: input.Password,
	}

	resp, err := r.AuthService.Login(ctx, req)
	if err != nil {
		return nil, err
	}

	return convertProtoToGraphQLAuthResponse(resp), nil
}

func (r *mutationResolver) VerifyEmail(ctx context.Context, token string) (*models.AuthResponse, error) {
	req := &pb.VerifyEmailRequest{
		Token: token,
	}

	resp, err := r.AuthService.VerifyEmail(ctx, req)
	if err != nil {
		return nil, err
	}

	return convertProtoToGraphQLAuthResponse(resp), nil
}

// Helper functions
func getUserIDFromContext(ctx context.Context) (string, error) {
	userID, ok := ctx.Value("userID").(string)
	fmt.Println(userID)
	if !ok {
		fmt.Println("Context does not contain userID")
		return "", errors.New("unauthorized: no user ID in context")
	}
	fmt.Println("Found userID in context:", userID)
	return userID, nil
}

func isAdmin(ctx context.Context) bool {
	isAdmin, ok := ctx.Value("isAdmin").(bool)
	return ok && isAdmin
}

// Conversion helpers
func convertProtoToGraphQLUser(protoUser *pb.User) *models.User {
	if protoUser == nil {
		return nil
	}

	// Convert string ID to ObjectID
	id, _ := primitive.ObjectIDFromHex(protoUser.Id)

	// Convert cart IDs
	cart := make([]string, len(protoUser.Cart))
	copy(cart, protoUser.Cart)

	// Convert address IDs
	addresses := make([]string, len(protoUser.Addresses))
	copy(addresses, protoUser.Addresses)

	// Handle optional string fields
	var mobileNumber, gender, dateOfBirth, image *string
	if protoUser.MobileNumber != "" {
		mobileNumber = &protoUser.MobileNumber
	}
	if protoUser.Gender != "" {
		gender = &protoUser.Gender
	}
	if protoUser.DateOfBirth != "" {
		dateOfBirth = &protoUser.DateOfBirth
	}
	if protoUser.Image != "" {
		image = &protoUser.Image
	}

	return &models.User{
		ID:           id.Hex(), // Convert ObjectID to string
		Name:         protoUser.Name,
		Email:        protoUser.Email,
		MobileNumber: mobileNumber,
		Gender:       gender,
		DateOfBirth:  dateOfBirth,
		Image:        image,
		IsVerified:   protoUser.IsVerified,
		IsAdmin:      protoUser.IsAdmin,
		Cart:         cart,
		Addresses:    addresses,
		IsBlocked:    protoUser.IsBlocked,
	}
}

func convertProtoToGraphQLUsers(protoUsers []*pb.User) []*models.User {
	users := make([]*models.User, len(protoUsers))
	for i, pu := range protoUsers {
		users[i] = convertProtoToGraphQLUser(pu)
	}
	return users
}

func convertProtoToGraphQLAuthResponse(protoResp *pb.AuthResponse) *models.AuthResponse {
	var token *string
	if protoResp.Token != "" {
		token = &protoResp.Token
	}

	return &models.AuthResponse{
		Message: protoResp.Message,
		Token:   token,
		User:    convertProtoToGraphQLUser(protoResp.User),
	}
}
