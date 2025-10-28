package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/zshstacks/markdown-zsh/config"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
)

// creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(&models.User{}, &models.RefreshToken{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	return db
}

// initializes test configuration
func setupTestConfig() {
	config.App = &config.AppConfig{
		JWT: config.JWTConfig{
			Secret:          "test-secret",
			AccessTokenTTL:  15,
			RefreshTokenTTL: 7,
		},
		Cookie: config.CookieConfig{
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}
}

// creates a test user with hashed password
func createTestUser(t *testing.T, db *gorm.DB) models.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	user := models.User{
		Model:            gorm.Model{ID: 1},
		UniqueID:         "test123",
		Email:            "test@example.com",
		Username:         "testuser",
		Password:         string(hashedPassword),
		IsEmailConfirmed: true,
	}

	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return user
}

// createRefreshToken creates a test refresh token
func createRefreshToken(t *testing.T, db *gorm.DB, userID uint) (string, string) {
	tokenID := uuid.NewString()
	secret := uuid.NewString()
	hash := sha256.Sum256([]byte(secret))

	refresh := models.RefreshToken{
		TokenId:   tokenID,
		TokenHash: hex.EncodeToString(hash[:]),
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := db.Create(&refresh).Error; err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}

	return tokenID, secret
}

// ============================================================================
// REGISTER TESTS
// ============================================================================

func TestRegister_Success(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"newuser@example.com","password":"password123","username":"newuser"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response struct {
		ID        uint      `json:"id"`
		UniqueID  string    `json:"unique_id"`
		Email     string    `json:"email"`
		Username  string    `json:"username"`
		CreatedAt time.Time `json:"created_at"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "newuser@example.com", response.Email)
	assert.Equal(t, "newuser", response.Username)
	assert.NotEmpty(t, response.UniqueID)
	assert.NotZero(t, response.ID)

	// Verify user in database
	var user models.User
	err = db.Where("email = ?", "newuser@example.com").First(&user).Error
	assert.NoError(t, err)
	assert.Equal(t, "newuser", user.Username)
}

func TestRegister_MissingEmail(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"password":"password123","username":"newuser"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Email is required!", httpErr.Message)
}

func TestRegister_MissingPassword(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"test@example.com","username":"newuser"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Password is required!", httpErr.Message)
}

func TestRegister_MissingUsername(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Username is required!", httpErr.Message)
}

func TestRegister_PasswordTooShort(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"short","username":"newuser"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Password must be at least 8 characters long", httpErr.Message)
}

func TestRegister_DuplicateEmail(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	createTestUser(t, db)

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"password123","username":"anotheruser"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
}

func TestRegister_InvalidJSON(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("invalid json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Register(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Failed to read body", httpErr.Message)
}

// ============================================================================
// REFRESH TESTS
// ============================================================================

func TestRefresh_Success(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)
	tokenID, secret := createRefreshToken(t, db, user.ID)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Set refresh token cookie
	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: tokenID + "." + secret,
	})

	err := Refresh(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Token refreshed", response["message"])

	// Check new cookies were set
	cookies := rec.Result().Cookies()
	assert.GreaterOrEqual(t, len(cookies), 2)

	// Verify old token was revoked
	var oldToken models.RefreshToken
	err = db.Where("token_id = ?", tokenID).First(&oldToken).Error
	assert.NoError(t, err)
	assert.NotNil(t, oldToken.RevokedAt)
	assert.NotNil(t, oldToken.ReplacedBy)

	// Verify new token was created
	var newToken models.RefreshToken
	err = db.Where("token_id = ?", *oldToken.ReplacedBy).First(&newToken).Error
	assert.NoError(t, err)
	assert.Nil(t, newToken.RevokedAt)
}

func TestRefresh_MissingCookie(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token missing", httpErr.Message)
}

func TestRefresh_InvalidTokenFormat(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "invalid-format",
	})

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid refresh token format", httpErr.Message)
}

func TestRefresh_TokenNotFound(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: uuid.NewString() + "." + uuid.NewString(),
	})

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token not found", httpErr.Message)
}

func TestRefresh_InvalidSecret(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)
	tokenID, _ := createRefreshToken(t, db, user.ID)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: tokenID + ".wrong-secret",
	})

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Invalid refresh token", httpErr.Message)
}

func TestRefresh_ExpiredToken(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)

	tokenID := uuid.NewString()
	secret := uuid.NewString()
	hash := sha256.Sum256([]byte(secret))

	refresh := models.RefreshToken{
		TokenId:   tokenID,
		TokenHash: hex.EncodeToString(hash[:]),
		UserID:    user.ID,
		IssuedAt:  time.Now().Add(-8 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	db.Create(&refresh)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: tokenID + "." + secret,
	})

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token is expired or revoked", httpErr.Message)
}

func TestRefresh_RevokedToken(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)

	tokenID := uuid.NewString()
	secret := uuid.NewString()
	hash := sha256.Sum256([]byte(secret))
	now := time.Now()

	refresh := models.RefreshToken{
		TokenId:   tokenID,
		TokenHash: hex.EncodeToString(hash[:]),
		UserID:    user.ID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RevokedAt: &now,
	}
	db.Create(&refresh)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: tokenID + "." + secret,
	})

	err := Refresh(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token is expired or revoked", httpErr.Message)
}

// ============================================================================
// LOGIN TESTS
// ============================================================================

func TestLogin_Success(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response struct {
		ID       uint   `json:"id"`
		UniqueID string `json:"unique_id"`
		Email    string `json:"email"`
		Username string `json:"username"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, response.ID)
	assert.Equal(t, user.UniqueID, response.UniqueID)
	assert.Equal(t, user.Email, response.Email)
	assert.Equal(t, user.Username, response.Username)

	// Check cookies were set
	cookies := rec.Result().Cookies()
	assert.GreaterOrEqual(t, len(cookies), 2, "Should set both access and refresh tokens")

	var tokenCookie, refreshCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "token" {
			tokenCookie = cookie
		}
		if cookie.Name == "refresh_token" {
			refreshCookie = cookie
		}
	}

	assert.NotNil(t, tokenCookie, "Access token cookie should be set")
	assert.NotEmpty(t, tokenCookie.Value)
	assert.True(t, tokenCookie.HttpOnly)
	assert.Equal(t, "/", tokenCookie.Path)

	assert.NotNil(t, refreshCookie, "Refresh token cookie should be set")
	assert.NotEmpty(t, refreshCookie.Value)
	assert.True(t, refreshCookie.HttpOnly)
	assert.Equal(t, "/", refreshCookie.Path)

	// Verify refresh token in database
	var refreshToken models.RefreshToken
	err = db.Where("user_id = ?", user.ID).First(&refreshToken).Error
	assert.NoError(t, err)
	assert.Equal(t, user.ID, refreshToken.UserID)
	assert.NotEmpty(t, refreshToken.TokenId)
	assert.NotEmpty(t, refreshToken.TokenHash)
	assert.False(t, refreshToken.ExpiresAt.Before(time.Now()))
}

func TestLogin_InvalidRequestBody(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("invalid json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Failed to read body", httpErr.Message)
}

func TestLogin_UserNotFound(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"nonexistent@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid email or password", httpErr.Message)
}

func TestLogin_InvalidPassword(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	createTestUser(t, db)

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Equal(t, "Invalid email or password", httpErr.Message)
}

func TestLogin_EmptyCredentials(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	reqBody := `{"email":"","password":""}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
}

func TestLogin_RefreshTokenCreation(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.NoError(t, err)

	// Verify refresh token in database
	var refreshToken models.RefreshToken
	err = db.Where("user_id = ?", user.ID).First(&refreshToken).Error
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken.TokenId)
	assert.NotEmpty(t, refreshToken.TokenHash)
	assert.Equal(t, user.ID, refreshToken.UserID)

	expectedExpiry := time.Now().Add(7 * 24 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, refreshToken.ExpiresAt, 5*time.Second)
}

func TestLogin_CookieSettings(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	createTestUser(t, db)

	e := echo.New()
	reqBody := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Login(c)

	assert.NoError(t, err)

	cookies := rec.Result().Cookies()
	for _, cookie := range cookies {
		assert.True(t, cookie.HttpOnly, "Cookie should be HttpOnly")
		assert.Equal(t, "/", cookie.Path, "Cookie path should be /")
		assert.Equal(t, config.App.Cookie.Secure, cookie.Secure)
		assert.Equal(t, config.App.Cookie.SameSite, cookie.SameSite)

		if cookie.Name == "token" {
			expectedMaxAge := config.App.JWT.AccessTokenTTL * 60
			assert.Equal(t, expectedMaxAge, cookie.MaxAge)
		}
		if cookie.Name == "refresh_token" {
			assert.Equal(t, 7*24*60*60, cookie.MaxAge)
		}
	}
}

// ============================================================================
// LOGOUT TESTS
// ============================================================================

func TestLogout_Success(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db
	user := createTestUser(t, db)
	tokenID, secret := createRefreshToken(t, db, user.ID)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: tokenID + "." + secret,
	})

	err := Logout(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]string
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Logged out", response["message"])

	// Check cookies were cleared
	cookies := rec.Result().Cookies()
	var tokenCookie, refreshCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "token" {
			tokenCookie = cookie
		}
		if cookie.Name == "refresh_token" {
			refreshCookie = cookie
		}
	}

	assert.NotNil(t, tokenCookie)
	assert.Equal(t, "", tokenCookie.Value)
	assert.Equal(t, -1, tokenCookie.MaxAge)

	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "", refreshCookie.Value)
	assert.Equal(t, -1, refreshCookie.MaxAge)

	// Verify token was revoked in database
	var refresh models.RefreshToken
	err = db.Where("token_id = ?", tokenID).First(&refresh).Error
	assert.NoError(t, err)
	assert.NotNil(t, refresh.RevokedAt)
}

func TestLogout_MissingCookie(t *testing.T) {
	setupTestConfig()
	db := setupTestDB(t)
	initializers.DB = db

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := Logout(c)

	assert.Error(t, err)
	var httpErr *echo.HTTPError
	ok := errors.As(err, &httpErr)
	assert.True(t, ok)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	assert.Equal(t, "Refresh token missing", httpErr.Message)
}
