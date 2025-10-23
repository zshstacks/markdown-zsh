package config

import (
	"net/http"
	"os"
	"strconv"
	"strings"
)

var App *AppConfig

type AppConfig struct {
	Environment string
	Server      ServerConfig
	Database    DatabaseConfig
	Cookie      CookieConfig
	JWT         JWTConfig
	CORS        CORSConfig
}

type ServerConfig struct {
	Port         string
	ReadTimeout  int
	WriteTimeout int
	Debug        bool
}

type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime int
}

type CookieConfig struct {
	Secure   bool
	SameSite http.SameSite
}

type JWTConfig struct {
	Secret          string
	AccessTokenTTL  int //minute
	RefreshTokenTTL int //day
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

func Init() {
	env := getEnv("APP_ENV", "development")
	isProd := strings.ToLower(env) == "production"

	App = &AppConfig{
		Environment: env,

		Server: ServerConfig{
			Port:         getEnv("PORT", "8000"),
			ReadTimeout:  getEnvAsInt("READ_TIMEOUT", 10),
			WriteTimeout: getEnvAsInt("WRITE_TIMEOUT", 10),
			Debug:        !isProd, // Debug only in development
		},

		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "DB_HOST"),
			Port:            getEnv("DB_PORT", "DB_PORT"),
			User:            getEnv("DB_USER", "DB_USER"),
			Password:        getEnv("DB_PASSWORD", "DB_PASSWORD"),
			Name:            getEnv("DB_NAME", "DB_NAME"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsInt("DB_CONN_MAX_LIFETIME", 300),
		},

		Cookie: CookieConfig{
			Secure:   isProd,
			SameSite: getSameSite(isProd),
		},

		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", "JWT_SECRET"),
			AccessTokenTTL:  getEnvAsInt("JWT_ACCESS_TTL", 15),
			RefreshTokenTTL: getEnvAsInt("JWT_REFRESH_TTL", 7),
		},

		CORS: CORSConfig{
			AllowedOrigins: getCORSOrigins(isProd),
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Origin", "Content-Type", "Authorization"},
		},
	}
}

//helpers

func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getSameSite(isProd bool) http.SameSite {
	if isProd {
		return http.SameSiteStrictMode
	}
	return http.SameSiteLaxMode
}

func getCORSOrigins(isProd bool) []string {
	if isProd {
		origins := os.Getenv("CORS_ORIGINS")
		if origins != "" {
			return strings.Split(origins, ",")
		}
		return []string{"https://sssss.com"}
	}
	//dev
	return []string{"http://localhost:3000", "http://localhost:8000"}
}

func (c *AppConfig) IsProduction() bool {
	return strings.ToLower(c.Environment) == "production"
}

func (c *AppConfig) IsDevelopment() bool {
	return !c.IsProduction()
}
