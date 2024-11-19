package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

)

type User struct {
	ID                 primitive.ObjectID   `bson:"_id,omitempty"`
	Name               string               `bson:"name"`
	Email              string               `bson:"email"`
	Password           string               `bson:"password"`
	MobileNumber       string               `bson:"mobile_number,omitempty"`
	Gender             string               `bson:"gender,omitempty"`
	DateOfBirth        string               `bson:"date_of_birth,omitempty"`
	Image              string               `bson:"image,omitempty"`
	IsVerified         bool                 `bson:"is_verified"`
	IsAdmin            bool                 `bson:"is_admin"`
	Cart               []primitive.ObjectID `bson:"cart,omitempty"`
	Addresses          []primitive.ObjectID `bson:"addresses,omitempty"`
	IsBlocked          bool                 `bson:"is_blocked"`
	VerifyToken        string               `bson:"verify_token,omitempty"`
	VerifyTokenExpires time.Time            `bson:"verify_token_expires,omitempty"`
	CreatedAt          time.Time            `bson:"created_at"`
	UpdatedAt          time.Time            `bson:"updated_at"`
}

type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Token     string             `bson:"token"`
	ExpiresAt time.Time          `bson:"expires_at"`
	CreatedAt time.Time          `bson:"created_at"`
}
