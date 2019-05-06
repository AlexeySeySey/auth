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
	E1 error        `json:"e1"`
}

func MakeLogoutEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(LogoutRequest)
		e1 := s.Logout(ctx, req.Key)
		return LogoutResponse{
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

func (e Endpoints) Logout(ctx context.Context, key entities.Key) (e1 error) {
	request := LogoutRequest{Key: key}
	response, err := e.LogoutEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(LogoutResponse).E1
}

func (e Endpoints) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	request := UserRegistrationAttemptRequest{Creds: creds}
	response, err := e.UserRegistrationAttemptEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UserRegistrationAttemptResponse).Err
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
	Key entities.Key `json:"key"`
}

// BlockUserResponse collects the response parameters for the BlockUser method.
type BlockUserResponse struct {
	Err error `json:"err"`
}

// MakeBlockUserEndpoint returns an endpoint that invokes BlockUser on the service.
func MakeBlockUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(BlockUserRequest)
		err := s.BlockUser(ctx, req.Key)
		return BlockUserResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r BlockUserResponse) Failed() error {
	return r.Err
}

// UnblockUserRequest collects the request parameters for the UnblockUser method.
type UnblockUserRequest struct {
	Key entities.Key `json:"key"`
}

// UnblockUserResponse collects the response parameters for the UnblockUser method.
type UnblockUserResponse struct {
	Err error `json:"err"`
}

// MakeUnblockUserEndpoint returns an endpoint that invokes UnblockUser on the service.
func MakeUnblockUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UnblockUserRequest)
		err := s.UnblockUser(ctx, req.Key)
		return UnblockUserResponse{Err: err}, nil
	}
}

// Failed implements Failer.
func (r UnblockUserResponse) Failed() error {
	return r.Err
}

// BlockUser implements Service. Primarily useful in a client.
func (e Endpoints) BlockUser(ctx context.Context, key entities.Key) (err error) {
	request := BlockUserRequest{Key: key}
	response, err := e.BlockUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(BlockUserResponse).Err
}

// UnblockUser implements Service. Primarily useful in a client.
func (e Endpoints) UnblockUser(ctx context.Context, key entities.Key) (err error) {
	request := UnblockUserRequest{Key: key}
	response, err := e.UnblockUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UnblockUserResponse).Err
}

type SearchUsersRequest struct {
	Key entities.Key `json:"key"`
}

type SearchUsersResponse struct {
	Users []entities.User `json:"users"`
	Err error `json:"error"`
}

func MakeSearchUsersEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(SearchUsersRequest)
		users, err := s.SearchUsers(ctx, req.Key)
		return SearchUsersResponse{Users: users, Err: err}, nil
	}
}

func (r SearchUsersResponse) Failed() error {
	return r.Err
}

func (e Endpoints) SearchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) {
	request := SearchUsersRequest{Key: key}
	response, err := e.SearchUsersEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(SearchUsersResponse).Users, response.(SearchUsersResponse).Err
}

type DropUserRequest struct {
	Key entities.Key `json:"key"`
}

type DropUserResponse struct {
	Err error `json:"error"`
}

func MakeDropUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(DropUserRequest)
		err := s.DropUser(ctx, req.Key)
		return DropUserResponse{Err: err}, nil
	}
}

func (r DropUserResponse) Failed() error {
	return r.Err
}

func (e Endpoints) DropUser(ctx context.Context, key entities.Key) (err error) {
	request := DropUserRequest{Key: key}
	response, err := e.DropUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(DropUserResponse).Err
}


/////////////////////
type UpdateUserRequest struct {
	Key entities.Key `json:"key"`
	User entities.User `json:"user"`
}

type UpdateUserResponse struct {
	Err error `json:"error"`
}

func MakeUpdateUserEndpoint(s service.AuthService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(UpdateUserRequest)
		err := s.UpdateUser(ctx, req.User, req.Key)
		return UpdateUserResponse{Err: err}, nil
	}
}

func (r UpdateUserResponse) Failed() error {
	return r.Err
}

func (e Endpoints) UpdateUser(ctx context.Context, user entities.User, key entities.Key) (err error) {
	request := UpdateUserRequest{Key: key, User: user}
	response, err := e.UpdateUserEndpoint(ctx, request)
	if err != nil {
		return
	}
	return response.(UpdateUserResponse).Err
}
/////////////////////////