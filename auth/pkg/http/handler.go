package http

import (
	"context"
	"encoding/json"
	"errors"
	http1 "net/http"
	endpoint "todo_SELF/auth/pkg/endpoint"

	http "github.com/go-kit/kit/transport/http"
	handlers "github.com/gorilla/handlers"
	mux "github.com/gorilla/mux"
)

func makeRegisterHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST", "OPTIONS").Path("/register").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.RegisterEndpoint, decodeRegisterRequest, encodeRegisterResponse, options...)))
}

func decodeRegisterRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.RegisterRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeRegisterResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	// w.Header().Set("Access-Control-Allow-Origin", "*")
	// w.Header().Set("Access-Control-Request-Method", "*")
	// w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, GET, POST, PATCH, DELETE, PUT")
	// w.Header().Set("Access-Control-Allow-Headers", "*")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeLoginHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/login").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.LoginEndpoint, decodeLoginRequest, encodeLoginResponse, options...)))
}

func decodeLoginRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.LoginRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeLoginResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeAccessHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/access").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.AccessEndpoint, decodeAccessRequest, encodeAccessResponse, options...)))
}

func decodeAccessRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.AccessRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeAccessResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeLogoutHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/logout").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.LogoutEndpoint, decodeLogoutRequest, encodeLogoutResponse, options...)))
}

func decodeLogoutRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.LogoutRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeLogoutResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeUserRegistrationAttemptHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/user-registration-attempt").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserRegistrationAttemptEndpoint, decodeUserRegistrationAttemptRequest, encodeUserRegistrationAttemptResponse, options...)))
}

func decodeUserRegistrationAttemptRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserRegistrationAttemptRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeUserRegistrationAttemptResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}
func ErrorEncoder(_ context.Context, err error, w http1.ResponseWriter) {
	w.WriteHeader(err2code(err))
	json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})
}
func ErrorDecoder(r *http1.Response) error {
	var w errorWrapper
	if err := json.NewDecoder(r.Body).Decode(&w); err != nil {
		return err
	}
	return errors.New(w.Error)
}

func err2code(err error) int {
	return http1.StatusInternalServerError
}

type errorWrapper struct {
	Error string `json:"error"`
}

func makeRegisterNewUserFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/register-new-user-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.RegisterNewUserFormEndpoint, decodeRegisterNewUserFormRequest, encodeRegisterNewUserFormResponse, options...)))
}

func decodeRegisterNewUserFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.RegisterNewUserFormRequest{}

	return req, nil
}

func encodeRegisterNewUserFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeUserLoginFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/user-login-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserLoginFormEndpoint, decodeUserLoginFormRequest, encodeUserLoginFormResponse, options...)))
}

func decodeUserLoginFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserLoginFormRequest{}

	return req, nil

}

func encodeUserLoginFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeUserRegisterFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/user-register-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserRegisterFormEndpoint, decodeUserRegisterFormRequest, encodeUserRegisterFormResponse, options...)))
}

func decodeUserRegisterFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserRegisterFormRequest{}

	return req, nil
}

func encodeUserRegisterFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

func makeFetchUsersHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/fetch-users").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}),  handlers.AllowedHeaders([]string{"*"}))(http.NewServer(endpoints.FetchUsersEndpoint, decodeFetchUsersRequest, encodeFetchUsersResponse, options...)))
}

func decodeFetchUsersRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.FetchUsersRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func encodeFetchUsersResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.Header().Set("Access-Control-Allow-Origin", "*")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeBlockUserHandler creates the handler logic
func makeBlockUserHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/block-user").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.BlockUserEndpoint, decodeBlockUserRequest, encodeBlockUserResponse, options...)))
}

// decodeBlockUserRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeBlockUserRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.BlockUserRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeBlockUserResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeBlockUserResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeUnblockUserHandler creates the handler logic
func makeUnblockUserHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/unblock-user").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UnblockUserEndpoint, decodeUnblockUserRequest, encodeUnblockUserResponse, options...)))
}

// decodeUnblockUserRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeUnblockUserRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UnblockUserRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeUnblockUserResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeUnblockUserResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}
