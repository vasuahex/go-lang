// internal/config/config.go
package config

import (
    "log"
    "os"
    "strconv"

    "github.com/joho/godotenv"
)

type Config struct {
    MongoURI     string
    DatabaseName string
    GRPCPort     string
    HTTPPort     string
    SMTPHost     string
    SMTPPort     int
    SMTPUsername string
    SMTPPassword string
    SMTPFrom     string
    JWTSecret    string
}

func LoadConfig() *Config {
    // Load .env file if it exists
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }

    smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))

    return &Config{
        MongoURI:     getEnv("MONGO_URI", "mongodb://localhost:27017"),
        DatabaseName: getEnv("DATABASE_NAME", "auth_db"),
        GRPCPort:     getEnv("GRPC_PORT", "50051"),
        HTTPPort:     getEnv("HTTP_PORT", "8080"),
        SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
        SMTPPort:     smtpPort,
        SMTPUsername: getEnv("SMTP_USERNAME", ""),
        SMTPPassword: getEnv("SMTP_PASSWORD", ""),
        SMTPFrom:     getEnv("SMTP_FROM", ""),
        JWTSecret:    getEnv("JWT_SECRET", "your-secret-key"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}