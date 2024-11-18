package schema

import (
	"github.com/vasuahex/go-lang/internal/services"
)

// This resolver implements the schema interface
type Resolver struct {
	AuthService *services.AuthService
}


func NewResolver(authService *services.AuthService) *Resolver {
	return &Resolver{
		AuthService: authService,
	}
}
