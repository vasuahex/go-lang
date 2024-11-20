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

	"github.com/golang-jwt/jwt"
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
	jwtSecret         []byte
	revokedTokens     *mongo.Collection
	pb.UnimplementedAuthServiceServer
}

func NewAuthService(db *mongo.Database, emailService EmailService, jwtSecret string) *AuthService {
	// Start a background goroutine to cleanup expired sessions
	service := &AuthService{
		userCollection:    db.Collection("users"),
		sessionCollection: db.Collection("sessions"),
		emailService:      emailService,
		jwtSecret:         []byte(jwtSecret),
		revokedTokens: db.Collection("revoked_tokens"),
	}

	// Start periodic cleanup of expired sessions
	go service.startSessionCleanup()

	return service
}

// JWT token generation and claims
type Claims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	jwt.StandardClaims
}

func (s *AuthService) generateJWTToken(userID string, isAdmin bool) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expirationTime, nil
}

func (s *AuthService) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
    // Create a simple filter to check if the token exists in the revoked_tokens collection
    filter := bson.M{"token": token}
    
    count, err := s.revokedTokens.CountDocuments(ctx, filter)
    if err != nil {
        return false, err
    }
    
    return count > 0, nil
}

// RevokeToken adds a token to the revoked tokens list
func (s *AuthService) RevokeToken(ctx context.Context, token string) error {
    // Add the token to the revoked_tokens collection with a timestamp
    _, err := s.revokedTokens.InsertOne(ctx, bson.M{
        "token": token,
        "revoked_at": time.Now(),
    })
    return err
}

// Session cleanup
func (s *AuthService) startSessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			ctx := context.Background()
			_, err := s.sessionCollection.DeleteMany(ctx, bson.M{
				"expires_at": bson.M{"$lt": time.Now()},
			})
			if err != nil {
				fmt.Printf("Error cleaning up expired sessions: %v\n", err)
			}
		}
	}()
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
	token, expiresAt, err := s.generateJWTToken(user.ID.Hex(), user.IsAdmin)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate session token")
	}

	// Create session
	session := &models.Session{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	_, err = s.sessionCollection.InsertOne(ctx, session)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create session")
	}

	return &pb.AuthResponse{
		Message: "Login successful",
		Token:   token,
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
