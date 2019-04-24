package service

import (
	"context"
	"time"

	entities "todo_SELF/auth/pkg/entities"
	env "todo_SELF/auth/pkg/env"
	helper "todo_SELF/auth/pkg/helper"
	db "todo_SELF/auth/pkg/storage"

	log "github.com/go-kit/kit/log"
	"gopkg.in/mgo.v2/bson"

	ewrapper "github.com/pkg/errors"
)

var (
	Mongo  = db.Mongo{}
	Redis  = db.Redis{}
	Logger log.Logger
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

	/* __ TEMPORARILY DEPRECATED __ */
	// return admin form (display handled html page) for regitration new user
	RegisterNewUserForm(ctx context.Context) (page string, executer string, e0 error) // GET "/register-new-user-form"
	// return URL for html page (will be iframe, but page handles in auth service), where user can put his login and send it to Login() method
	UserLoginForm(ctx context.Context) (page string, executer string, e0 error) // GET "/user-login-form"
	// return URL for html page (will be iframe, but page handles in auth service), where user can put his info (email, name and comment), and send it to UserRegistrationAttempt() method
	UserRegisterForm(ctx context.Context) (page string, executer string, e0 error) // GET "/user-register-form"
	/* __ TEMPORARILY DEPRECATED __ */
}

type basicAuthService struct{}

func (b *basicAuthService) Register(ctx context.Context, creds entities.Credentials) (err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()

	_, err = Redis.Connect()
	if err != nil {
		return err
	}
	var (
		ch          = make(chan error, 1)
		contentType = "text/html"
		subject     = "Registration Accepted!"
	)
	if err := helper.IsValidCreds(creds); err != nil {
		return err
	}

	user, isAdmin, err := helper.IsUserExist(creds, &Mongo)
	if err == nil {
		return ewrapper.Wrap(env.ErrUserAlreadyExist, env.ErrRegister)
	}

	Logger.Log("User: ", user)

	tokenKey, err := helper.GenerateRandomString()
	if err != nil {
		return err
	}

	expDateTime := helper.TokenExpiration()
	id, err := Mongo.Insert(entities.User{
		Email:    creds.Email,
		Password: creds.Password,
		Name:     creds.Name,
		Token: entities.Key{
			Token:      tokenKey,
			IsAdmin:    isAdmin,
			Expired_at: expDateTime,
		}})
	if err != nil {
		return err
	}

	if err = Redis.Set(tokenKey, id); err != nil {
		return err
	}

	/*

		SEND EMAIL

		TO USER

		NOT TO ADMIN

	*/

	go helper.SendEmail(creds.Email, env.AdminEmail, subject, creds.Message, contentType, ch)
	err = <-ch
	if err != nil {
		return err
	}

	return nil
}

func (b *basicAuthService) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return entities.Key{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()

	_, err = Redis.Connect()
	if err != nil {
		return entities.Key{}, err
	}
	if err := helper.IsValidCreds(creds); err != nil {
		return entities.Key{}, err
	}

	user, isAdmin, err := helper.IsUserExist(creds, &Mongo)
	if err != nil {
		return entities.Key{}, err
	}

	var logger log.Logger
	logger.Log("User: ", user)

	token, err := helper.GenerateRandomString()
	if err != nil {
		return entities.Key{}, err
	}

	newKey := entities.Key{
		Token:      token,
		IsAdmin:    isAdmin,
		Expired_at: helper.TokenExpiration(),
	}
	if err := Mongo.Update(bson.M{"_id": user.Id}, bson.M{"Token": newKey}); err != nil {
		return entities.Key{}, err
	}

	// delete old and set new, becouse token - is key
	if err = Redis.Del(user.Token.Token); err != nil {
		return entities.Key{}, err
	}
	if err = Redis.Set(token, user.Id); err != nil {
		return entities.Key{}, err
	}

	return entities.Key{
		Token:      token,
		IsAdmin:    isAdmin,
		Expired_at: helper.TokenExpiration(),
	}, nil
}

func (b *basicAuthService) Access(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return entities.Key{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()

	_, err = Redis.Connect()
	if err != nil {
		return entities.Key{}, err
	}
	_, err = helper.IsValidToken(&Redis, key)
	if err != nil {
		return entities.Key{}, err
	}
	return key, nil
}

func (b *basicAuthService) Logout(ctx context.Context, key entities.Key) (e0 entities.Key, e1 error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return entities.Key{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()

	_, err = Redis.Connect()
	if err != nil {
		return entities.Key{}, err
	}
	key.Expired_at = time.Now().Format(helper.TimeFormat)

	userId, err := helper.IsValidToken(&Redis, key)
	if err != nil {
		return entities.Key{}, err
	}

	if err := Mongo.Update(bson.M{"_id": userId}, bson.M{"Token": key}); err != nil {
		return entities.Key{}, err
	}

	return key, nil
}

func (b *basicAuthService) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	var (
		ch          = make(chan error)
		contentType = "text/html"
		subject     = "New Registration Attempt!"
	)

	go helper.SendEmail(creds.Email, env.AdminEmail, subject, creds.Message, contentType, ch)
	err = <-ch
	return err
}

// DEPRECATED
func (b *basicAuthService) RegisterNewUserForm(ctx context.Context) (page string, executer string, e0 error) {
	return "", "", nil
}

// DEPRECATED
func (b *basicAuthService) UserLoginForm(ctx context.Context) (page string, executer string, e0 error) {
	return "", "", nil
}

// DEPRECATED
func (b *basicAuthService) UserRegisterForm(ctx context.Context) (page string, executer string, e0 error) {
	return "", "", nil
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
