package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vasuahex/go-lang/internal/models"
	pb "github.com/vasuahex/go-lang/proto/auth"

)

type AuthService struct {
	userCollection    *mongo.Collection
	sessionCollection *mongo.Collection
	emailService      EmailService
	pb.UnimplementedAuthServiceServer
}

func NewAuthService(db *mongo.Database, emailService EmailService) *AuthService {
	return &AuthService{
		userCollection:    db.Collection("users"),
		sessionCollection: db.Collection("sessions"),
		emailService:      emailService,
	}
}

// Helper functions
func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func validateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	return nil
}

func (s *AuthService) convertUserToProto(user *models.User) *pb.User {
	return &pb.User{
		Id:           user.ID.Hex(),
		Name:         user.Name,
		Email:        user.Email,
		MobileNumber: user.MobileNumber,
		Gender:       user.Gender,
		DateOfBirth:  user.DateOfBirth,
		Image:        user.Image,
		IsVerified:   user.IsVerified,
		IsAdmin:      user.IsAdmin,
		IsBlocked:    user.IsBlocked,
		Cart:         convertObjectIDsToStrings(user.Cart),
		Addresses:    convertObjectIDsToStrings(user.Addresses),
	}
}

func convertObjectIDsToStrings(ids []primitive.ObjectID) []string {
	strings := make([]string, len(ids))
	for i, id := range ids {
		strings[i] = id.Hex()
	}
	return strings
}

// Register implements the Register RPC method
func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	// Validate input
	if strings.TrimSpace(req.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	if !validateEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email format")
	}

	if err := validatePassword(req.Password); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Check if user exists
	var existingUser models.User
	err := s.userCollection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		return nil, status.Error(codes.AlreadyExists, "email already reg istered")
	} else if err != mongo.ErrNoDocuments {
		return nil, status.Error(codes.Internal, "database error")
	}

	// Generate verification token
	verifyToken, err := generateToken(32)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate verification token")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to hash password")
	}

	// Create user
	now := time.Now()
	user := &models.User{
		Name:               req.Name,
		Email:              req.Email,
		Password:           string(hashedPassword),
		IsVerified:         false,
		IsAdmin:            false,
		IsBlocked:          false,
		VerifyToken:        verifyToken,
		VerifyTokenExpires: now.Add(24 * time.Hour),
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	result, err := s.userCollection.InsertOne(ctx, user)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	// Get the inserted ID
	user.ID = result.InsertedID.(primitive.ObjectID)

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verifyToken); err != nil {
		// Log the error but don't fail the registration
		fmt.Printf("Failed to send verification email: %v\n", err)
	}

	return &pb.AuthResponse{
		Message: "Registration successful. Please verify your email.",
		User:    s.convertUserToProto(user),
	}, nil
}

// Login implements the Login RPC method
func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	// Validate input
	if !validateEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email format")
	}

	if strings.TrimSpace(req.Password) == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	// Find user
	var user models.User
	err := s.userCollection.FindOne(ctx, bson.M{"email": req.Email}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, status.Error(codes.NotFound, "invalid email or password")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}

	// Check if user is blocked
	if user.IsBlocked {
		return nil, status.Error(codes.PermissionDenied, "account is blocked")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}

	// Check if email is verified
	if !user.IsVerified {
		return nil, status.Error(codes.PermissionDenied, "email not verified")
	}

	// Generate session token
	sessionToken, err := generateToken(32)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate session token")
	}

	// Create session
	now := time.Now()
	session := &models.Session{
		UserID:    user.ID,
		Token:     sessionToken,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	_, err = s.sessionCollection.InsertOne(ctx, session)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create session")
	}

	return &pb.AuthResponse{
		Message: "Login successful",
		Token:   sessionToken,
		User:    s.convertUserToProto(&user),
	}, nil
}

// VerifyEmail implements the VerifyEmail RPC method
func (s *AuthService) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.AuthResponse, error) {
	// Validate input
	if strings.TrimSpace(req.Token) == "" {
		return nil, status.Error(codes.InvalidArgument, "verification token is required")
	}

	// Find user with the verification token
	now := time.Now()
	filter := bson.M{
		"verify_token":         req.Token,
		"verify_token_expires": bson.M{"$gt": now},
		"is_verified":          false,
	}

	update := bson.M{
		"$set": bson.M{
			"is_verified":          true,
			"verify_token":         nil,
			"verify_token_expires": nil,
			"updated_at":           now,
		},
	}

	var user models.User
	err := s.userCollection.FindOneAndUpdate(ctx, filter, update).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, status.Error(codes.NotFound, "invalid or expired verification token")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}

	return &pb.AuthResponse{
		Message: "Email verified successfully",
		User:    s.convertUserToProto(&user),
	}, nil
}

// Add these methods to your AuthService struct in auth_service.go

func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*pb.User, error) {
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user ID")
	}

	var user models.User
	err = s.userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, status.Error(codes.NotFound, "user not found")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}

	return s.convertUserToProto(&user), nil
}

func (s *AuthService) GetUsers(ctx context.Context) ([]*pb.User, error) {
	cursor, err := s.userCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, status.Error(codes.Internal, "failed to decode users")
	}

	result := make([]*pb.User, len(users))
	for i, user := range users {
		result[i] = s.convertUserToProto(&user)
	}

	return result, nil
}
