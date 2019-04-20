package service

import (
	"context"
	entities "todo_SELF/auth/pkg/entities"

	log "github.com/go-kit/kit/log"
)

// Middleware describes a service middleware.
type Middleware func(AuthService) AuthService

type loggingMiddleware struct {
	logger log.Logger
	next   AuthService
}

// LoggingMiddleware takes a logger as a dependency
// and returns a AuthService Middleware.
func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next AuthService) AuthService {
		return &loggingMiddleware{logger, next}
	}

}

func (l loggingMiddleware) Register(ctx context.Context, creds entities.Credentials) (err error) {
	defer func() {
		l.logger.Log("method", "Register", "creds", creds, "err", err)
	}()
	return l.next.Register(ctx, creds)
}
func (l loggingMiddleware) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	defer func() {
		l.logger.Log("method", "Login", "creds", creds, "key", key, "err", err)
	}()
	return l.next.Login(ctx, creds)
}
func (l loggingMiddleware) Access(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	defer func() {
		l.logger.Log("method", "Access", "key", key, "e0", e0, "e1", e1)
	}()
	return l.next.Access(ctx, key)
}
func (l loggingMiddleware) Logout(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	defer func() {
		l.logger.Log("method", "Logout", "key", key, "e0", e0, "e1", e1)
	}()
	return l.next.Logout(ctx, key)
}
func (l loggingMiddleware) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	defer func() {
		l.logger.Log("method", "UserRegistrationAttempt", "creds", creds, "err", err)
	}()
	return l.next.UserRegistrationAttempt(ctx, creds)
}

func (l loggingMiddleware) RegisterNewUserForm(ctx context.Context) (page string, e0 error) {
	defer func() {
		l.logger.Log("method", "RegisterNewUserForm", "e0", e0, "string", page)
	}()
	return l.next.RegisterNewUserForm(ctx)
}
func (l loggingMiddleware) UserLoginForm(ctx context.Context) (page string, e0 error) {
	defer func() {
		l.logger.Log("method", "UserLoginForm", "e0", e0, "string", page)
	}()
	return l.next.UserLoginForm(ctx)
}
func (l loggingMiddleware) UserRegisterForm(ctx context.Context) (page string, e0 error) {
	defer func() {
		l.logger.Log("method", "UserRegisterForm", "e0", e0, "string", page)
	}()
	return l.next.UserRegisterForm(ctx)
}
