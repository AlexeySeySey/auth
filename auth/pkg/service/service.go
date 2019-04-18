package service

import (
	"context"
	"todo_SELF/auth/pkg/entities"
)

// AuthService describes the service.
type AuthService interface {
	// registration new user (by admin)
	Register(ctx context.Context, creds entities.Credentials) (err error) // POST "/register"

	// log in by client
	Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) // POST "/login"

	// acces to something
	Access(ctx context.Context, key entities.Key) (entities.Key, error) // POST "/access"

	// logout for speicific client
	Logout(ctx context.Context, key entities.Key) (entities.Key, error) // POST "/logout"

	// users attempt to register (send email to admin)
	UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) // POST "/user-registration-attempt"

	// return admin form (display handled html page) for regitration new user
	RegisterNewUserForm(ctx context.Context) error // GET "/register-new-user-form"

	// return URL for html page (will be iframe, but page handles in auth service), where user can put his login and send it to Login() method
	UserLoginForm(ctx context.Context) error // GET "/user-login-form"

	// return URL for html page (will be iframe, but page handles in auth service), where user can put his info (email, name and comment), and send it to UserRegistrationAttempt() method
	UserRegisterForm(ctx context.Context) error // GET "/user-register-form"
}

type basicAuthService struct{}

func (b *basicAuthService) Register(ctx context.Context, creds entities.Credentials) (err error) {
	// TODO implement the business logic of Register
	return err
}
func (b *basicAuthService) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	// TODO implement the business logic of Login
	return key, err
}
func (b *basicAuthService) Access(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	// TODO implement the business logic of Access
	return e0, e1
}
func (b *basicAuthService) Logout(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	// TODO implement the business logic of Logout
	return e0, e1
}
func (b *basicAuthService) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	// TODO implement the business logic of UserRegistrationAttempt
	return err
}

func (b *basicAuthService) RegisterNewUserForm(ctx context.Context) (e0 error) {
	// TODO implement the business logic of RegisterNewUserForm
	return e0
}
func (b *basicAuthService) UserLoginForm(ctx context.Context) (e0 error) {
	// TODO implement the business logic of UserLoginForm
	return e0
}
func (b *basicAuthService) UserRegisterForm(ctx context.Context) (e0 error) {
	// TODO implement the business logic of UserRegisterForm
	return e0
}

// NewBasicAuthService returns a naive, stateless implementation of AuthService.
func NewBasicAuthService() AuthService {
	return &basicAuthService{}
}

// New returns a AuthService with all of the expected middleware wired in.
func New(middleware []Middleware) AuthService {
	var svc AuthService = NewBasicAuthService()
	for _, m := range middleware {
		svc = m(svc)
	}
	return svc
}
