package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"savviAuth/internal/auth"
	"savviAuth/internal/common"
)

type AuthHandler struct {
	AuthService auth.AuthService
}

func NewAuthHandler(authService auth.AuthService) *AuthHandler {
	return &AuthHandler{AuthService: authService}
}

func (h *AuthHandler) RegisterRoutes() {
	http.HandleFunc("/auth/login", h.Login)
	http.HandleFunc("/auth/register", h.Register)
	http.HandleFunc("/login/google", h.LoginGoogle)
	http.HandleFunc("/callback/google", h.CallbackGoogle)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {

}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {

}

func (h *AuthHandler) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	/*
		Google OAuth login
	*/
	params := url.Values{}
	params.Add("client_id", os.Getenv("GOOGLE_CLIENT_ID"))
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("redirect_uri", os.Getenv("GOOGLE_REDIRECT_URI"))
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")

	url := fmt.Sprintf("%s?%s", os.Getenv("GOOGLE_AUTH_URL"), params.Encode())

}

func (h *AuthHandler) CallbackGoogle(w http.ResponseWriter, r *http.Request) {
	/*
		Google OAuth callback
	*/
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not provided by Google", http.StatusBadRequest)
		return
	}

	tokenParams := url.Values{}
	tokenParams.Add("code", code)
	tokenParams.Add("grant_type", "authorization_code")
	tokenParams.Add("redirect_uri", os.Getenv("GOOGLE_REDIRECT_URI"))
	tokenParams.Add("client_id", os.Getenv("GOOGLE_CLIENT_ID"))
	tokenParams.Add("client_secret", os.Getenv("GOOGLE_CLIENT_SECRET"))

	tokenResponse, err := http.PostForm(os.Getenv("GOOGLE_TOKEN_URL"), tokenParams)
	if err != nil {
		http.Error(w, "Failed to get access token from Google", http.StatusBadRequest)
		return
	}

	if tokenResponse.StatusCode != http.StatusOK {
		http.Error(w, "Failed to get access token from Google", http.StatusBadRequest)
		return
	}

	tokenData := make(map[string]interface{})
	err = json.NewDecoder(tokenResponse.Body).Decode(&tokenData)
	if err != nil {
		http.Error(w, "Failed to decode access token from Google", http.StatusBadRequest)
		return
	}

	userInfoResponse, err := http.Get(fmt.Sprintf("%s?%s", os.Getenv("GOOGLE_USERINFO_URL"), tokenData["access_token"]))
	if err != nil {
		http.Error(w, "Failed to get user info from Google", http.StatusBadRequest)
		return
	}

	if userInfoResponse.StatusCode != http.StatusOK {
		http.Error(w, "Failed to get user info from Google", http.StatusBadRequest)
		return
	}

	userInfo := make(map[string]interface{})
	err = json.NewDecoder(userInfoResponse.Body).Decode(&userInfo)
	if err != nil {
		http.Error(w, "Failed to decode user info from Google", http.StatusBadRequest)
		return
	}

	email := userInfo["email"].(string)
	if email == "" {
		http.Error(w, "Email not provided by Google", http.StatusBadRequest)
		return
	}

	dbUser, err := h.AuthService.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	accessToken, err := h.AuthService.GenerateTokenPair(dbUser.ID)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}

	common.JSONResponse(w, http.StatusOK, map[string]string{"access_token": accessToken})

}
