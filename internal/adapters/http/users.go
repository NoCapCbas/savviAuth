package http

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"savviAuth/internal/common"
	"savviAuth/internal/users"
)

type UserHandler struct {
	UserService users.UserService
}

func NewUserHandler(userService users.UserService) *UserHandler {
	return &UserHandler{UserService: userService}
}

func (h *UserHandler) RegisterRoutes() {
	// handle users
	http.HandleFunc("/users", h.handleUsers)
	// handle user
	http.HandleFunc("/users/", h.handleUser)

}

func (h *UserHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.CreateUser(w, r)
	case http.MethodGet:
		h.ListUsers(w, r)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *UserHandler) handleUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/users/"):]
	switch r.Method {
	case http.MethodGet:
		h.GetUser(w, r, id)
	case http.MethodPut:
		h.UpdateUser(w, r, id)
	case http.MethodPost:
		if len(id) > 0 && r.URL.Path[len("/users/"):] == id+"/disable" {
			h.DisableUser(w, r, id)
		} else {
			http.Error(w, "Not found", http.StatusNotFound)
		}
	case http.MethodDelete:
		h.DeleteUser(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	newUser, err := h.UserService.Register(user.Username, user.Email, user.Password)
	if err != nil {
		common.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	common.JSONResponse(w, http.StatusCreated, newUser)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		return
	}

	user, err := h.UserService.GetUser(id)
	if err != nil {
		common.JSONResponse(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	common.JSONResponse(w, http.StatusOK, user)
}

func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		return
	}

	var updateData users.User
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
		return
	}

	updateData.ID = id
	if err := h.UserService.UpdateUser(&updateData); err != nil {
		common.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	common.JSONResponse(w, http.StatusOK, updateData)
}

func (h *UserHandler) DisableUser(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		return
	}

	if err := h.UserService.DisableUser(id); err != nil {
		common.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	common.JSONResponse(w, http.StatusOK, map[string]string{"message": "User disabled successfully"})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		common.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		return
	}

	if err := h.UserService.DeleteUser(id); err != nil {
		common.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	common.JSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})

}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.UserService.ListUsers()
	if err != nil {
		common.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	common.JSONResponse(w, http.StatusOK, users)
}
