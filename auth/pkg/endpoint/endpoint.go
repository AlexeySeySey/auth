package endpoint

import (
	"context"
	entities "todo_SELF/auth/pkg/entities"
	service "todo_SELF/auth/pkg/service"

	endpoint "github.com/go-kit/kit/endpoint"
)

// RegisterRequest collects the request parameters for the Register method.
type RegisterRequest struct {
	Creds entities.Credentials `json:"creds"`
}

// RegisterResponse collects the response parameters for the Register method.
type RegisterResponse struct {
	Err error `json:"err"`
}

// MakeRegisterEndpoint returns an endpoint that invokes Register on the service.
func MakeRegisterEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(RegisterRequest)
		err := s.Register(ctx, req.Creds)
		return RegisterResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r RegisterResponse) Failed() error {
	return r.Err
}

// LoginRequest collects the request parameters for the Login method.
type LoginRequest struct {
	Creds entities.Credentials `json:"creds"`
}

// LoginResponse collects the response parameters for the Login method.
type LoginResponse struct {
	Key entities.Key `json:"key"`
	Err error        `json:"err"`
}

// MakeLoginEndpoint returns an endpoint that invokes Login on the service.
func MakeLoginEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LoginRequest)
		key, err := s.Login(ctx, req.Creds)
		return LoginResponse{
			Err: err,
			Key: key,
		}, nil
	}
}

// Failed implements Failer.
func (r LoginResponse) Failed() error {
	return r.Err
}

// AccessRequest collects the request parameters for the Access method.
type AccessRequest struct {
	Key entities.Key `json:"key"`
}

// AccessResponse collects the response parameters for the Access method.
type AccessResponse struct {
	E0 entities.Key `json:"e0"`
	E1 error        `json:"e1"`
}

// MakeAccessEndpoint returns an endpoint that invokes Access on the service.
func MakeAccessEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(AccessRequest)
		e0, e1 := s.Access(ctx, req.Key)
		return AccessResponse{
			E0: e0,
			E1: e1,
		}, nil
	}
}

// Failed implements Failer.
func (r AccessResponse) Failed() error {
	return r.E1
}

// LogoutRequest collects the request parameters for the Logout method.
type LogoutRequest struct {
	Key entities.Key `json:"key"`
}

// LogoutResponse collects the response parameters for the Logout method.
type LogoutResponse struct {
	E0 entities.Key `json:"e0"`
	E1 error        `json:"e1"`
}

// MakeLogoutEndpoint returns an endpoint that invokes Logout on the service.
func MakeLogoutEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LogoutRequest)
		e0, e1 := s.Logout(ctx, req.Key)
		return LogoutResponse{
			E0: e0,
			E1: e1,
		}, nil
	}
}

// Failed implements Failer.
func (r LogoutResponse) Failed() error {
	return r.E1
}

// UserRegistrationAttemptRequest collects the request parameters for the UserRegistrationAttempt method.
type UserRegistrationAttemptRequest struct {
	Creds entities.Credentials `json:"creds"`
}

// UserRegistrationAttemptResponse collects the response parameters for the UserRegistrationAttempt method.
type UserRegistrationAttemptResponse struct {
	Err error `json:"err"`
}

// MakeUserRegistrationAttemptEndpoint returns an endpoint that invokes UserRegistrationAttempt on the service.
func MakeUserRegistrationAttemptEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UserRegistrationAttemptRequest)
		err := s.UserRegistrationAttempt(ctx, req.Creds)
		return UserRegistrationAttemptResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r UserRegistrationAttemptResponse) Failed() error {
	return r.Err
}

// Failure is an interface that should be implemented by response types.
// Response encoders can check if responses are Failer, and if so they've
// failed, and if so encode them using a separate write path based on the error.
type Failure interface {
	Failed() error
}

// Register implements Service. Primarily useful in a client.
func (e Endpoints) Register(ctx context.Context, creds entities.Credentials) (err error) {
	request := RegisterRequest{Creds: creds}
	response, err := e.RegisterEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(RegisterResponse).Err
}

// Login implements Service. Primarily useful in a client.
func (e Endpoints) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	request := LoginRequest{Creds: creds}
	response, err := e.LoginEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(LoginResponse).Key, response.(LoginResponse).Err
}

// Access implements Service. Primarily useful in a client.
func (e Endpoints) Access(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	request := AccessRequest{Key: key}
	response, err := e.AccessEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(AccessResponse).E0, response.(AccessResponse).E1
}

// Logout implements Service. Primarily useful in a client.
func (e Endpoints) Logout(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	request := LogoutRequest{Key: key}
	response, err := e.LogoutEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(LogoutResponse).E0, response.(LogoutResponse).E1
}

// UserRegistrationAttempt implements Service. Primarily useful in a client.
func (e Endpoints) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	request := UserRegistrationAttemptRequest{Creds: creds}
	response, err := e.UserRegistrationAttemptEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserRegistrationAttemptResponse).Err
}

// RegisterNewUserFormRequest collects the request parameters for the RegisterNewUserForm method.
type RegisterNewUserFormRequest struct{}

// RegisterNewUserFormResponse collects the response parameters for the RegisterNewUserForm method.
type RegisterNewUserFormResponse struct {
	Page string `json:"page"`
	Executer string `json:"executer"`
	E0   error  `json:"e0"`
}

// MakeRegisterNewUserFormEndpoint returns an endpoint that invokes RegisterNewUserForm on the service.
func MakeRegisterNewUserFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, executer, e0 := s.RegisterNewUserForm(ctx)
		return RegisterNewUserFormResponse{Page: page, Executer: executer, E0: e0}, nil
	}
}

// Failed implements Failer.
func (r RegisterNewUserFormResponse) Failed() error {
	return r.E0
}

// UserLoginFormRequest collects the request parameters for the UserLoginForm method.
type UserLoginFormRequest struct{}

// UserLoginFormResponse collects the response parameters for the UserLoginForm method.
type UserLoginFormResponse struct {
	Page string `json:"page"`
	Executer string `json:"executer"`
	E0   error  `json:"e0"`
}

// MakeUserLoginFormEndpoint returns an endpoint that invokes UserLoginForm on the service.
func MakeUserLoginFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, ex, e0 := s.UserLoginForm(ctx)
		return UserLoginFormResponse{Page: page, Executer: ex, E0: e0}, nil
	}
}

// Failed implements Failer.
func (r UserLoginFormResponse) Failed() error {
	return r.E0
}

// UserRegisterFormRequest collects the request parameters for the UserRegisterForm method.
type UserRegisterFormRequest struct{}

// UserRegisterFormResponse collects the response parameters for the UserRegisterForm method.
type UserRegisterFormResponse struct {
	Page string `json:"page"`
	Executer string `json:"executer"`
	E0   error  `json:"e0"`
}

// MakeUserRegisterFormEndpoint returns an endpoint that invokes UserRegisterForm on the service.
func MakeUserRegisterFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, ex, e0 := s.UserRegisterForm(ctx)
		return UserRegisterFormResponse{Page: page, Executer: ex, E0: e0}, nil
	}
}

// Failed implements Failer.
func (r UserRegisterFormResponse) Failed() error {
	return r.E0
}

// RegisterNewUserForm implements Service. Primarily useful in a client.
func (e Endpoints) RegisterNewUserForm(ctx context.Context) (page string, ex string, e0 error) {
	request := RegisterNewUserFormRequest{}
	response, err := e.RegisterNewUserFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(RegisterNewUserFormResponse).Page, response.(RegisterNewUserFormResponse).Executer, response.(RegisterNewUserFormResponse).E0
}

// UserLoginForm implements Service. Primarily useful in a client.
func (e Endpoints) UserLoginForm(ctx context.Context) (page string, ex string, e0 error) {
	request := UserLoginFormRequest{}
	response, err := e.UserLoginFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserLoginFormResponse).Page, response.(UserLoginFormResponse).Executer, response.(UserLoginFormResponse).E0
}

// UserRegisterForm implements Service. Primarily useful in a client.
func (e Endpoints) UserRegisterForm(ctx context.Context) (page string, ex string, e0 error) {
	request := UserRegisterFormRequest{}
	response, err := e.UserRegisterFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserRegisterFormResponse).Page, response.(UserRegisterFormResponse).Executer, response.(UserRegisterFormResponse).E0
}
