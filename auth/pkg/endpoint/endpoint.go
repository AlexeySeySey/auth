package endpoint

import (
	"context"
	entities "todo_SELF/auth/pkg/entities"
	service "todo_SELF/auth/pkg/service"

	endpoint "github.com/go-kit/kit/endpoint"
)

type RegisterRequest struct {
	Creds entities.Credentials `json:"creds"`
}

type RegisterResponse struct {
	Err error `json:"err"`
}

func MakeRegisterEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(RegisterRequest)
		err := s.Register(ctx, req.Creds)
		return RegisterResponse{Err: err}, nil
	}
}

func (r RegisterResponse) Failed() error {
	return r.Err
}

type LoginRequest struct {
	Creds entities.Credentials `json:"creds"`
}

type LoginResponse struct {
	Key entities.Key `json:"key"`
	Err error        `json:"err"`
}

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

func (r LoginResponse) Failed() error {
	return r.Err
}

type AccessRequest struct {
	Key entities.Key `json:"key"`
}

type AccessResponse struct {
	E0 entities.Key `json:"e0"`
	E1 error        `json:"e1"`
}

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

func (r AccessResponse) Failed() error {
	return r.E1
}

type LogoutRequest struct {
	Key entities.Key `json:"key"`
}

type LogoutResponse struct {
	E0 entities.Key `json:"e0"`
	E1 error        `json:"e1"`
}

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

func (r LogoutResponse) Failed() error {
	return r.E1
}

type UserRegistrationAttemptRequest struct {
	Creds entities.Credentials `json:"creds"`
}

type UserRegistrationAttemptResponse struct {
	Err error `json:"err"`
}

func MakeUserRegistrationAttemptEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UserRegistrationAttemptRequest)
		err := s.UserRegistrationAttempt(ctx, req.Creds)
		return UserRegistrationAttemptResponse{Err: err}, nil
	}
}

func (r UserRegistrationAttemptResponse) Failed() error {
	return r.Err
}

type Failure interface {
	Failed() error
}

func (e Endpoints) Register(ctx context.Context, creds entities.Credentials) (err error) {
	request := RegisterRequest{Creds: creds}
	response, err := e.RegisterEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(RegisterResponse).Err
}

func (e Endpoints) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	request := LoginRequest{Creds: creds}
	response, err := e.LoginEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(LoginResponse).Key, response.(LoginResponse).Err
}

func (e Endpoints) Access(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	request := AccessRequest{Key: key}
	response, err := e.AccessEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(AccessResponse).E0, response.(AccessResponse).E1
}

func (e Endpoints) Logout(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	request := LogoutRequest{Key: key}
	response, err := e.LogoutEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(LogoutResponse).E0, response.(LogoutResponse).E1
}

func (e Endpoints) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	request := UserRegistrationAttemptRequest{Creds: creds}
	response, err := e.UserRegistrationAttemptEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserRegistrationAttemptResponse).Err
}

type RegisterNewUserFormRequest struct{}

type RegisterNewUserFormResponse struct {
	Page     string `json:"page"`
	Executer string `json:"executer"`
	E0       error  `json:"e0"`
}

func MakeRegisterNewUserFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, executer, e0 := s.RegisterNewUserForm(ctx)
		return RegisterNewUserFormResponse{Page: page, Executer: executer, E0: e0}, nil
	}
}

func (r RegisterNewUserFormResponse) Failed() error {
	return r.E0
}

type UserLoginFormRequest struct{}

type UserLoginFormResponse struct {
	Page     string `json:"page"`
	Executer string `json:"executer"`
	E0       error  `json:"e0"`
}

func MakeUserLoginFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, ex, e0 := s.UserLoginForm(ctx)
		return UserLoginFormResponse{Page: page, Executer: ex, E0: e0}, nil
	}
}

func (r UserLoginFormResponse) Failed() error {
	return r.E0
}

type UserRegisterFormRequest struct{}

type UserRegisterFormResponse struct {
	Page     string `json:"page"`
	Executer string `json:"executer"`
	E0       error  `json:"e0"`
}

func MakeUserRegisterFormEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		page, ex, e0 := s.UserRegisterForm(ctx)
		return UserRegisterFormResponse{Page: page, Executer: ex, E0: e0}, nil
	}
}

func (r UserRegisterFormResponse) Failed() error {
	return r.E0
}

func (e Endpoints) RegisterNewUserForm(ctx context.Context) (page string, ex string, e0 error) {
	request := RegisterNewUserFormRequest{}
	response, err := e.RegisterNewUserFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(RegisterNewUserFormResponse).Page, response.(RegisterNewUserFormResponse).Executer, response.(RegisterNewUserFormResponse).E0
}

func (e Endpoints) UserLoginForm(ctx context.Context) (page string, ex string, e0 error) {
	request := UserLoginFormRequest{}
	response, err := e.UserLoginFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserLoginFormResponse).Page, response.(UserLoginFormResponse).Executer, response.(UserLoginFormResponse).E0
}

func (e Endpoints) UserRegisterForm(ctx context.Context) (page string, ex string, e0 error) {
	request := UserRegisterFormRequest{}
	response, err := e.UserRegisterFormEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserRegisterFormResponse).Page, response.(UserRegisterFormResponse).Executer, response.(UserRegisterFormResponse).E0
}

type FetchUsersRequest struct {
	Key entities.Key `json:"key"`
}

type FetchUsersResponse struct {
	Users []entities.User `json:"users"`
	Err   error           `json:"err"`
}

func MakeFetchUsersEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(FetchUsersRequest)
		users, err := s.FetchUsers(ctx, req.Key)
		return FetchUsersResponse{
			Err:   err,
			Users: users,
		}, nil
	}
}

func (r FetchUsersResponse) Failed() error {
	return r.Err
}

func (e Endpoints) FetchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) {
	request := FetchUsersRequest{Key: key}
	response, err := e.FetchUsersEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(FetchUsersResponse).Users, response.(FetchUsersResponse).Err
}

// BlockUserRequest collects the request parameters for the BlockUser method.
type BlockUserRequest struct {
	Id string `json:"id"`
}

// BlockUserResponse collects the response parameters for the BlockUser method.
type BlockUserResponse struct {
	Err error `json:"err"`
}

// MakeBlockUserEndpoint returns an endpoint that invokes BlockUser on the service.
func MakeBlockUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(BlockUserRequest)
		err := s.BlockUser(ctx, req.Id)
		return BlockUserResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r BlockUserResponse) Failed() error {
	return r.Err
}

// UnblockUserRequest collects the request parameters for the UnblockUser method.
type UnblockUserRequest struct {
	Id string `json:"id"`
}

// UnblockUserResponse collects the response parameters for the UnblockUser method.
type UnblockUserResponse struct {
	Err error `json:"err"`
}

// MakeUnblockUserEndpoint returns an endpoint that invokes UnblockUser on the service.
func MakeUnblockUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UnblockUserRequest)
		err := s.UnblockUser(ctx, req.Id)
		return UnblockUserResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r UnblockUserResponse) Failed() error {
	return r.Err
}

// BlockUser implements Service. Primarily useful in a client.
func (e Endpoints) BlockUser(ctx context.Context, id string) (err error) {
	request := BlockUserRequest{Id: id}
	response, err := e.BlockUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(BlockUserResponse).Err
}

// UnblockUser implements Service. Primarily useful in a client.
func (e Endpoints) UnblockUser(ctx context.Context, id string) (err error) {
	request := UnblockUserRequest{Id: id}
	response, err := e.UnblockUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UnblockUserResponse).Err
}
