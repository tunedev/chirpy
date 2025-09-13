package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"context"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/tunedev/chirpy/internal/auth"
	"github.com/tunedev/chirpy/internal/database"
)

type CTX_KEY string

type ChirpsWithJSON struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	UserID    string `json:"user_id"`
	Body      string `json:"body"`
}

type UserWithJSON struct {
	ID           string `json:"id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	Email        string `json:"email"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type userParam struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

const (
	SANITIZED_CHIRP_BODY = CTX_KEY("CHIRP:SANITIZED_BODY")
	USER_ID_CTX_KEY      = CTX_KEY("CHIRP:AUTH_USER_ID")
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
	polkaApiKey    string
}

type chirpReqBody struct {
	CleanedBody string
}

type webhookReqBody struct {
	Event string `json:"event"`
	Data  struct {
		UserId string `json:"user_id"`
	} `json:"data"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metric := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
	`, metric)))
}

// func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
// 	cfg.fileserverHits.Store(0)
// 	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
// 	w.WriteHeader(http.StatusOK)
// }

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errResp struct {
		Error string `json:"error"`
	}

	respondWithJSON(w, code, errResp{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "failed to marshal JSON response"}`))
		return
	}
	w.WriteHeader(code)
	w.Write(dat)
}

func (cfg *apiConfig) validate_chirp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type Payload struct {
			Body   string `json:"body"`
			UserID string `json:"user_id"`
		}
		defer r.Body.Close()
		reqBody := Payload{}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		maxChirpLength := 140
		if len(reqBody.Body) > maxChirpLength {
			respondWithError(w, http.StatusBadRequest, "Chirp is too long")
			return
		}

		var cleanedBodyArr []string

		for _, word := range strings.Split(reqBody.Body, " ") {
			normalizedWord := strings.ToLower(word)
			if normalizedWord == "kerfuffle" || normalizedWord == "sharbert" || normalizedWord == "fornax" {
				cleanedBodyArr = append(cleanedBodyArr, "****")
			} else {
				cleanedBodyArr = append(cleanedBodyArr, word)
			}
		}
		resp := chirpReqBody{
			CleanedBody: strings.Join(cleanedBodyArr, " "),
		}

		newReq := r.WithContext(context.WithValue(r.Context(), SANITIZED_CHIRP_BODY, resp))

		next.ServeHTTP(w, newReq)
	})
}

func (cfg *apiConfig) addNewUser(w http.ResponseWriter, r *http.Request) {

	defer r.Body.Close()

	newUsr := userParam{}
	err := json.NewDecoder(r.Body).Decode(&newUsr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Json Body, expect email in json body")
		return
	}
	if newUsr.Password == "" {
		respondWithError(w, http.StatusBadRequest, "password required in the json body")
		return
	}

	hashedPass, err := auth.HashPassword(newUsr.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "internal server error hashing password")
		return
	}
	newUserDetails, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		HashedPassword: hashedPass,
		Email:          newUsr.Email,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("encountered an error: %s, while saving new user", err.Error()))
		return
	}

	respondWithJSON(w, http.StatusCreated, UserWithJSON{
		ID:          newUserDetails.ID.String(),
		CreatedAt:   newUserDetails.CreatedAt.String(),
		UpdatedAt:   newUserDetails.UpdatedAt.String(),
		Email:       newUserDetails.Email,
		IsChirpyRed: newUserDetails.IsChirpyRed,
	})
}

func (cfg *apiConfig) adminDevUsersReset(w http.ResponseWriter, r *http.Request) {
	currentPlatform := os.Getenv("PLATFORM")
	if currentPlatform != "dev" {
		respondWithError(w, http.StatusForbidden, "operation is only permitted in a dev environment")
		return
	}

	err := cfg.db.DevAdminDBReset(r.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("error resetting the dev env, %s", err.Error()))
		return
	}

	respondWithJSON(w, http.StatusOK, struct{}{})
}

func (cfg *apiConfig) getUserIdFromCTXOrRespondWithErr(w http.ResponseWriter, r *http.Request) *uuid.UUID {
	userId, ok := r.Context().Value(USER_ID_CTX_KEY).(uuid.UUID)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "error parsing userId")
		return nil
	}
	return &userId
}

func (cfg *apiConfig) saveNewChirp(w http.ResponseWriter, r *http.Request) {
	chirpReqBody, ok := r.Context().Value(SANITIZED_CHIRP_BODY).(chirpReqBody)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Invalid type convertion")
		return
	}
	userID, ok := r.Context().Value(USER_ID_CTX_KEY).(uuid.UUID)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "error with the userid type stored in the context")
		return
	}
	newChirp, err := cfg.db.SaveChirps(r.Context(), database.SaveChirpsParams{
		Body:   chirpReqBody.CleanedBody,
		UserID: userID,
	})

	if err != nil {
		fmt.Println("Full error details while saving chirps to the db =====>>>>>>>>>>>>", err, "userID:", userID)
		respondWithError(w, http.StatusInternalServerError, "error saving chirps to the db")
		return
	}

	respondWithJSON(w, http.StatusCreated, ChirpsWithJSON{
		ID:        newChirp.ID.String(),
		UserID:    newChirp.UserID.String(),
		CreatedAt: newChirp.CreatedAt.String(),
		UpdatedAt: newChirp.UpdatedAt.String(),
		Body:      newChirp.Body,
	})
}

func (cfg *apiConfig) fetchAllChirps(w http.ResponseWriter, r *http.Request) {
	var chirps []database.Chirp
	var err error
	authorId := r.URL.Query().Get("author_id")
	sortOrder := r.URL.Query().Get("sort")
	if len(authorId) > 0 {
		var parsedUserId uuid.UUID
		parsedUserId, err = uuid.Parse(authorId)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "author_id must be a valid uuid")
			return
		}
		chirps, err = cfg.db.GetAllUsersChirps(r.Context(), parsedUserId)
	} else {
		chirps, err = cfg.db.GetAllChirps(r.Context())
	}
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error fetching all chirps from the database")
		return
	}

	if sortOrder == "desc" {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].CreatedAt.After(chirps[j].CreatedAt) })
	}

	resBody := make([]ChirpsWithJSON, len(chirps))
	for i, chirp := range chirps {
		resBody[i] = ChirpsWithJSON{
			ID:        chirp.ID.String(),
			UserID:    chirp.UserID.String(),
			CreatedAt: chirp.CreatedAt.String(),
			UpdatedAt: chirp.UpdatedAt.String(),
			Body:      chirp.Body,
		}
	}
	respondWithJSON(w, http.StatusOK, resBody)
}

func (cfg *apiConfig) GetChirpsById(w http.ResponseWriter, r *http.Request) {
	chirpsId := r.PathValue("chirpID")
	parsedChirpId, err := uuid.Parse(chirpsId)

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "chirp id mus be a valid uuid")
		return
	}

	chirpDetails, err := cfg.db.GetChirpsById(r.Context(), parsedChirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("chirps with ID: %s Not Found", chirpsId))
		return

	}

	respondWithJSON(w, http.StatusOK, ChirpsWithJSON{
		ID:        chirpDetails.ID.String(),
		UserID:    chirpDetails.UserID.String(),
		CreatedAt: chirpDetails.CreatedAt.String(),
		UpdatedAt: chirpDetails.UpdatedAt.String(),
		Body:      chirpDetails.Body,
	})
}

func (cfg *apiConfig) login(w http.ResponseWriter, r *http.Request) {
	var loginParam userParam
	defer r.Body.Close()

	err := json.NewDecoder(r.Body).Decode(&loginParam)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Error parsing request body to json")
		return
	}

	userDetails, err := cfg.db.GetUserByEmail(r.Context(), loginParam.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error getting user details from db")
		return
	}

	err = auth.CheckPasswordHash(loginParam.Password, userDetails.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	refreshTokenExpiry := time.Now().Add(60 * 24 * time.Hour)

	token, err := auth.MakeJWT(userDetails.ID, cfg.jwtSecret, 60*time.Second)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	newRefreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error generating new refresh token")
		return
	}

	refreshTokenEntry, err := cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     newRefreshToken,
		UserID:    userDetails.ID,
		ExpiresAt: refreshTokenExpiry,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error saving persisting refresh token")
		return
	}

	respondWithJSON(w, http.StatusOK, UserWithJSON{
		ID:           userDetails.ID.String(),
		CreatedAt:    userDetails.CreatedAt.String(),
		UpdatedAt:    userDetails.UpdatedAt.String(),
		Email:        userDetails.Email,
		Token:        token,
		RefreshToken: refreshTokenEntry.Token,
		IsChirpyRed:  userDetails.IsChirpyRed,
	})
}

func (cfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "refresh token bearer it required")
		return
	}

	refreshTokenDetailsWithUser, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		fmt.Println("an error occurred while fething refresh token details", err)
		respondWithError(w, http.StatusUnauthorized, "error validating refresh token")
		return
	}

	if refreshTokenDetailsWithUser.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "refresh token has been revoked")
		return
	}

	newToken, err := auth.MakeJWT(refreshTokenDetailsWithUser.UserID, cfg.jwtSecret, 60*time.Second)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error generating new token")
		return
	}

	respondWithJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{
		Token: newToken,
	})
}

func (cfg *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenStr, err := auth.GetToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "refresh token bearer it required")
		return
	}

	err = cfg.db.RevokeRefreshToken(r.Context(), refreshTokenStr)
	if err != nil {
		fmt.Println("what is the fuss about ===>>>>>", err)
		respondWithError(w, http.StatusInternalServerError, "error revoking refresh token")
		return
	}

	respondWithJSON(w, http.StatusNoContent, nil)
}

func (cfg *apiConfig) authenticateAndAddUserToReqContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := auth.GetToken(r.Header)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Authentication is required for this endpoint")
			return
		}
		authUserId, err := auth.ValidateJWT(tokenStr, cfg.jwtSecret)
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "invalid auth credentials")
			return
		}
		newReqCtx := r.WithContext(context.WithValue(r.Context(), USER_ID_CTX_KEY, authUserId))

		next.ServeHTTP(w, newReqCtx)
	})
}

func (cfg *apiConfig) updateUserRecords(w http.ResponseWriter, r *http.Request) {
	userId := *cfg.getUserIdFromCTXOrRespondWithErr(w, r)
	var newUserData userParam
	defer r.Body.Close()
	err := json.NewDecoder(r.Body).Decode(&newUserData)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error parsing request body")
		return
	}

	hashedPass, err := auth.HashPassword(newUserData.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error hashing password")
		return
	}

	newUserInfo, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userId,
		HashedPassword: hashedPass,
		Email:          newUserData.Email,
	})
	if err != nil {
		fmt.Println("There is something wrong with updating user details in the DB", err)
		respondWithError(w, http.StatusInternalServerError, "error storing updated details in db")
	}

	respondWithJSON(w, http.StatusOK, UserWithJSON{
		ID:          newUserInfo.ID.String(),
		CreatedAt:   newUserInfo.CreatedAt.String(),
		UpdatedAt:   newUserInfo.UpdatedAt.String(),
		Email:       newUserInfo.Email,
		IsChirpyRed: newUserInfo.IsChirpyRed,
	})
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	userId := *cfg.getUserIdFromCTXOrRespondWithErr(w, r)

	chirpId := r.PathValue("chirpID")
	parsedChirpId, err := uuid.Parse(chirpId)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "chirp id must be a valid uuid")
		return
	}

	chirpDetails, err := cfg.db.GetChirpsById(r.Context(), parsedChirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, fmt.Sprintf("chirp with id: %s not found", chirpId))
		return
	}

	if chirpDetails.UserID != userId {
		respondWithError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	if err := cfg.db.DeleteChirp(r.Context(), parsedChirpId); err != nil {
		respondWithError(w, http.StatusInternalServerError, "error deleting chirp from DB")
		return
	}

	respondWithJSON(w, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handleWebhook(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetToken(r.Header)
	if err != nil || apiKey != cfg.polkaApiKey {
		respondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		return
	}
	var webhookBody webhookReqBody
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&webhookBody); err != nil {
		respondWithError(w, http.StatusBadRequest, "unable to parse request body")
		return
	}

	if webhookBody.Event != "user.upgraded" {
		respondWithJSON(w, http.StatusNoContent, nil)
		return
	}

	parsedUserId, err := uuid.Parse(webhookBody.Data.UserId)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid user_id value must be a valid uuid")
		return
	}

	err = cfg.db.UpgradeUser(r.Context(), parsedUserId)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error occurred while upgrading user in DB")
		return
	}

	respondWithJSON(w, http.StatusNoContent, nil)
}

func main() {
	godotenv.Load()

	jwtSecretFromEnv := os.Getenv("JWT_SECRET")
	if jwtSecretFromEnv == "" {
		log.Fatal("Expect JWT_SECRET to be stored in the enviroment variable")
	}
	polkaApiKey := os.Getenv("POLKA_KEY")
	if polkaApiKey == "" {
		log.Fatal("Expect POLKA_KEY to be in the environment variable")
	}

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error while creating database %v", err)
	}
	dbQueries := database.New(db)
	mux := http.NewServeMux()
	port := "8021"
	srv := http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	apiCfg := apiConfig{
		db:          dbQueries,
		jwtSecret:   jwtSecretFromEnv,
		polkaApiKey: polkaApiKey,
	}

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handleWebhook)

	mux.HandleFunc("POST /admin/reset", apiCfg.adminDevUsersReset)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)

	mux.HandleFunc("POST /api/users", apiCfg.addNewUser)
	mux.Handle("PUT /api/users", apiCfg.authenticateAndAddUserToReqContext(http.HandlerFunc(apiCfg.updateUserRecords)))

	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshToken)

	mux.Handle("POST /api/chirps", apiCfg.validate_chirp(apiCfg.authenticateAndAddUserToReqContext(http.HandlerFunc(apiCfg.saveNewChirp))))
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.GetChirpsById)
	mux.Handle("DELETE /api/chirps/{chirpID}", apiCfg.authenticateAndAddUserToReqContext(http.HandlerFunc(apiCfg.deleteChirp)))
	mux.HandleFunc("GET /api/chirps", apiCfg.fetchAllChirps)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(http.StatusText(http.StatusOK) + "\n"))
	})

	srv.ListenAndServe()
}
