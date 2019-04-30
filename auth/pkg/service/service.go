package service

import (
	"context"
	"fmt"
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
	// "creds":{...}
	UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) // POST "/user-registration-attempt"

	// return all users from database, if requester client is admin
	FetchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) // POST "/fetch-users"

	// set user as Banned
	BlockUser(ctx context.Context, id string) (err error) // POST "/block-user"

	// remove Banned status from user
	UnblockUser(ctx context.Context, id string) (err error) // POST "/unblock-user"

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
	if err := helper.IsValidCreds(creds); err != nil {
		return err
	}

	user, isAdmin, err := helper.IsUserExist(creds, &Mongo)
	if err != nil {
		return err
	}
	if user != entities.User{} {
		return ewrapper.Wrap(env.ErrUserAlreadyExist, env.ErrRegister)
	}
	fmt.Println(user)

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

	if err = Redis.Set(tokenKey, string(id)); err != nil {
		return err
	}

	var (
		contentType = "text/html"
		subject     = "Registration Accepted!"
	)

	return helper.SendEmail(env.AdminEmail, creds.Email, subject, creds.Message, contentType)
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

	fmt.Println(user)

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
	if err = Redis.Set(token, string(user.Id)); err != nil {
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
		contentType = "text/html"
		subject     = "New Registration Attempt!"
	)
	return helper.SendEmail(creds.Email, env.AdminEmail, subject, creds.Message, contentType)
}

func (b *basicAuthService) FetchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return []entities.User{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()

	users, err = Mongo.FetchUsers()
	if err != nil {
		return []entities.User{}, err
	}

	return users, err
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

func (b *basicAuthService) BlockUser(ctx context.Context, id string) (err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	err = Mongo.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"isbanned": true})
	return err
}
func (b *basicAuthService) UnblockUser(ctx context.Context, id string) (err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	err = Mongo.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"isbanned": false})
	return err
}
