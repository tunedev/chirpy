package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// function to hash password before storing it in the db
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// function to validate previously hashed password
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// MakeJWT creates a signed token form the object passed
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  &jwt.NumericDate{Time: time.Now()},
		ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(expiresIn)},
		Subject:   userID.String(),
	})

	return token.SignedString([]byte(tokenSecret))
}

// ValidateJWT confirms that the token passed is valid and signed by this server
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claim := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claim,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})

	var emptyUUID uuid.UUID

	if err != nil {
		return emptyUUID, err
	}

	if !token.Valid {
		return emptyUUID, fmt.Errorf("token is invalid")
	}

	subject := claim.Subject
	userId, err := uuid.Parse(subject)
	if err != nil {
		return emptyUUID, err
	}

	return userId, nil
}

func GetToken(headers http.Header) (string, error) {
	authInfo := headers.Get("Authorization")
	if authInfo == "" {
		return "", fmt.Errorf("no value present in the Authorization key of the header")
	}

	authComponents := strings.Fields(authInfo)
	if len(authComponents) != 2 {
		return "", fmt.Errorf("malformed bearer auth value in the authorization header")
	}
	if !slices.Contains([]string{"ApiKey", "Bearer"}, authComponents[0]) {
		return "", fmt.Errorf("malformed bearer auth value in the authorization header")
	}
	return authComponents[1], nil
}

func MakeRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}
