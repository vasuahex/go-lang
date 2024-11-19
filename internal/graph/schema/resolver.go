package schema

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vasuahex/go-lang/internal/models"
	"github.com/vasuahex/go-lang/internal/services"
	pb "github.com/vasuahex/go-lang/proto/auth"
)

// Input types
type RegisterInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Message string       `json:"message"`
	Token   string       `json:"token"`
	User    *models.User `json:"user"`
}

// Resolver struct holds dependencies
type Resolver struct {
	AuthService *services.AuthService
}

func NewResolver(authService *services.AuthService) *Resolver {
	return &Resolver{
		AuthService: authService,
	}
}

// Query resolvers
func (r *Resolver) Me(ctx context.Context) (*models.User, error) {
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

func (r *Resolver) Users(ctx context.Context) ([]*models.User, error) {
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
func (r *Resolver) Register(ctx context.Context, input RegisterInput) (*AuthResponse, error) {
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

func (r *Resolver) Login(ctx context.Context, input LoginInput) (*AuthResponse, error) {
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

func (r *Resolver) VerifyEmail(ctx context.Context, token string) (*AuthResponse, error) {
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
	if !ok {
		return "", errors.New("unauthorized: no user ID in context")
	}
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

	// Convert string IDs to ObjectIDs
	id, _ := primitive.ObjectIDFromHex(protoUser.Id)

	// Convert cart string IDs to ObjectIDs
	cart := make([]primitive.ObjectID, len(protoUser.Cart))
	for i, cartID := range protoUser.Cart {
		objID, _ := primitive.ObjectIDFromHex(cartID)
		cart[i] = objID
	}

	// Convert address string IDs to ObjectIDs
	addresses := make([]primitive.ObjectID, len(protoUser.Addresses))
	for i, addressID := range protoUser.Addresses {
		objID, _ := primitive.ObjectIDFromHex(addressID)
		addresses[i] = objID
	}

	return &models.User{
		ID:           id,
		Name:         protoUser.Name,
		Email:        protoUser.Email,
		MobileNumber: protoUser.MobileNumber,
		Gender:       protoUser.Gender,
		DateOfBirth:  protoUser.DateOfBirth,
		Image:        protoUser.Image,
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

func convertProtoToGraphQLAuthResponse(protoResp *pb.AuthResponse) *AuthResponse {
	return &AuthResponse{
		Message: protoResp.Message,
		Token:   protoResp.Token,
		User:    convertProtoToGraphQLUser(protoResp.User),
	}
}
