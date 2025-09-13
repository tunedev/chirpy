package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestPasswordHashCycle calls the auth.HashPassword and the auth.CaomparePassword to
// assert expected behaviors
func TestPasswordHashCycle(t *testing.T) {
	testData := []struct {
		passwordText     string
		password2Compare string
		shouldCompareErr bool
	}{
		{"password1", "password1", false},
		{"password2", "password1", true},
	}

	for _, testCase := range testData {
		hashedPass, err := HashPassword(testCase.passwordText)
		if err != nil {
			t.Error("HashPassword should never error")
		}

		err = CheckPasswordHash(testCase.password2Compare, hashedPass)
		if testCase.shouldCompareErr && err == nil {
			t.Errorf("Expected check password function to error but it did not")
		} else if !testCase.shouldCompareErr && err != nil {
			t.Errorf("Expected check password function not to error but it did")
		}
	}
}

func TestJWTLifeCycle(t *testing.T) {
	validSecret := "valid-test-jwt-secret"
	invalidSecret := "invalid-test-jwt-secret"
	testingData := []struct {
		userID              string
		jwtSecret           string
		shouldValidateError bool
		expireIn            time.Duration
	}{
		{"6666a8c4-22e1-4a8a-8de6-22a6c0173ce7", validSecret, false, time.Duration(50 * time.Second)},
		{"f3b442c3-69b0-4368-9f21-ddbcea81e62d", invalidSecret, true, time.Duration(50 * time.Second)},
		{"7cb683fc-7c56-4e74-b3b4-eeb777125238", validSecret, true, time.Duration(1 * time.Second)},
	}

	for _, testCase := range testingData {
		userId, err := uuid.Parse(testCase.userID)
		if err != nil {
			t.Errorf("Error parsing userid string, supply a uuid compliant string in test cases")
		}
		tokenString, err := MakeJWT(userId, validSecret, testCase.expireIn)
		if err != nil {
			fmt.Println("Error while making jwt kilo le fa ===>>>>>>>", err)
			t.Error("MakeJJWT should not error once all args are satisfied")
		}
		if testCase.expireIn == time.Duration(1*time.Second) {
			// test that it apropriately invalidates token when it has expired
			time.Sleep(time.Duration(2 * time.Second))
		}
		_, err = ValidateJWT(tokenString, testCase.jwtSecret)
		if testCase.shouldValidateError && err == nil {
			t.Errorf("expected the validation of this token to error, but it did not. Testcase details: %v", testCase)
		} else if !testCase.shouldValidateError && err != nil {
			fmt.Println("Error when none is expected, kilo fa ===>>>>>>>>>", err)
			t.Errorf("expected the validation of this token to not error, but it did. Testcase details: %v", testCase)
		}
	}
}

// Tests the ability to get the bearer token through the auth.GetToken function
func TestGetBearerToken(t *testing.T) {
	validTestToken := "test-token"
	testingData := []struct {
		headers     http.Header
		shouldError bool
	}{
		{http.Header{
			"Authorization": {fmt.Sprintf("Bearer %s", validTestToken)},
		}, false},
		{http.Header{}, true},
		{http.Header{"Authorization": {"some-random-string"}}, true},
	}

	for _, testCase := range testingData {
		token, err := GetToken(testCase.headers)
		if testCase.shouldError && err == nil {
			t.Error("expected GetToken to Error out, but it didn't")
		} else if !testCase.shouldError {
			if err != nil {
				t.Error("expected GetToken not to Error out, but it did")
			} else {
				if token != validTestToken {
					t.Errorf("invalid token gottend from GetToken expected: %s, got: %s", validTestToken, token)
				}
			}
		}
	}
}
