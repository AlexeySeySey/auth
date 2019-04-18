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

// makeRegisterHandler creates the handler logic
func makeRegisterHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/register").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.RegisterEndpoint, decodeRegisterRequest, encodeRegisterResponse, options...)))
}

// decodeRegisterRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeRegisterRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.RegisterRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeRegisterResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeRegisterResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeLoginHandler creates the handler logic
func makeLoginHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/login").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.LoginEndpoint, decodeLoginRequest, encodeLoginResponse, options...)))
}

// decodeLoginRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeLoginRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.LoginRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeLoginResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeLoginResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeAccessHandler creates the handler logic
func makeAccessHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/access").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.AccessEndpoint, decodeAccessRequest, encodeAccessResponse, options...)))
}

// decodeAccessRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeAccessRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.AccessRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeAccessResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeAccessResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeLogoutHandler creates the handler logic
func makeLogoutHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/logout").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.LogoutEndpoint, decodeLogoutRequest, encodeLogoutResponse, options...)))
}

// decodeLogoutRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeLogoutRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.LogoutRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeLogoutResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeLogoutResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeUserRegistrationAttemptHandler creates the handler logic
func makeUserRegistrationAttemptHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("POST").Path("/user-registration-attempt").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserRegistrationAttemptEndpoint, decodeUserRegistrationAttemptRequest, encodeUserRegistrationAttemptResponse, options...)))
}

// decodeUserRegistrationAttemptRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeUserRegistrationAttemptRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserRegistrationAttemptRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

// encodeUserRegistrationAttemptResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
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

// This is used to set the http status, see an example here :
// https://github.com/go-kit/kit/blob/master/examples/addsvc/pkg/addtransport/http.go#L133
func err2code(err error) int {
	return http1.StatusInternalServerError
}

type errorWrapper struct {
	Error string `json:"error"`
}

// makeRegisterNewUserFormHandler creates the handler logic
func makeRegisterNewUserFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/register-new-user-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.RegisterNewUserFormEndpoint, decodeRegisterNewUserFormRequest, encodeRegisterNewUserFormResponse, options...)))
}

// decodeRegisterNewUserFormRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeRegisterNewUserFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.RegisterNewUserFormRequest{}
	//err := json.NewDecoder(r.Body).Decode(&req)
	return req, nil
}

// encodeRegisterNewUserFormResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeRegisterNewUserFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeUserLoginFormHandler creates the handler logic
func makeUserLoginFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/user-login-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserLoginFormEndpoint, decodeUserLoginFormRequest, encodeUserLoginFormResponse, options...)))
}

// decodeUserLoginFormRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeUserLoginFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserLoginFormRequest{}
	//err := json.NewDecoder(r.Body).Decode(&req)
	return req, nil
	// TODO
}

// encodeUserLoginFormResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeUserLoginFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}

// makeUserRegisterFormHandler creates the handler logic
func makeUserRegisterFormHandler(m *mux.Router, endpoints endpoint.Endpoints, options []http.ServerOption) {
	m.Methods("GET").Path("/user-register-form").Handler(handlers.CORS(handlers.AllowedMethods([]string{"POST"}), handlers.AllowedHeaders([]string{"*"}), handlers.AllowedOrigins([]string{"*"}))(http.NewServer(endpoints.UserRegisterFormEndpoint, decodeUserRegisterFormRequest, encodeUserRegisterFormResponse, options...)))
}

// decodeUserRegisterFormRequest is a transport/http.DecodeRequestFunc that decodes a
// JSON-encoded request from the HTTP request body.
func decodeUserRegisterFormRequest(_ context.Context, r *http1.Request) (interface{}, error) {
	req := endpoint.UserRegisterFormRequest{}
	//err := json.NewDecoder(r.Body).Decode(&req)
	return req, nil
}

// encodeUserRegisterFormResponse is a transport/http.EncodeResponseFunc that encodes
// the response as JSON to the response writer
func encodeUserRegisterFormResponse(ctx context.Context, w http1.ResponseWriter, response interface{}) (err error) {
	if f, ok := response.(endpoint.Failure); ok && f.Failed() != nil {
		ErrorEncoder(ctx, f.Failed(), w)
		return nil
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err = json.NewEncoder(w).Encode(response)
	return
}
