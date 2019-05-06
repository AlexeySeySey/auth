package service

import (
	"context"
	"fmt"

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
	Logout(ctx context.Context, key entities.Key) error // POST "/logout"

	// users attempt to register (send email to admin)
	// "creds":{...}
	UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) // POST "/user-registration-attempt"

	// return all users from database, if requester client is admin
	FetchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) // POST "/fetch-users"

	// set user as Banned
	BlockUser(ctx context.Context, key entities.Key) (err error) // POST "/block-user"

	// remove Banned status from user
	UnblockUser(ctx context.Context, key entities.Key) (err error) // POST "/unblock-user"

	SearchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) // POST "/search-users"

	DropUser(ctx context.Context, key entities.Key) (err error) // POST "/drop-user"

	UpdateUser(ctx context.Context, user entities.User, key entities.Key) (err error) // POST "/update-user"

}

type basicAuthService struct{}

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

func (b *basicAuthService) Register(ctx context.Context, creds entities.Credentials) (err error) {
	if err := helper.IsValidCreds(creds); err != nil {
		return err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	_, exist, err := helper.IsUserExist(creds, &Mongo)
	if err != nil {
		return err
	}
	if exist == true {
		return ewrapper.Wrap(env.ErrUserAlreadyExist, env.ErrRegister)
	}
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
			IsAdmin:    false,
			Expired_at: expDateTime,
		}})
	if err != nil {
		return err
	}
	_, err = Redis.Connect()
	if err != nil {
		return err
	}
	if err = Redis.Set(tokenKey, string(id.Hex())); err != nil {
		return err
	}
	const (
		contentType = "text/html"
		subject     = "Registration"
	)
	return helper.SendEmail(env.AdminEmail, creds.Email, subject, creds.Message, contentType)
}

func (b *basicAuthService) Login(ctx context.Context, creds entities.Credentials) (key entities.Key, err error) {
	if err := helper.IsValidCreds(creds); err != nil {
		return entities.Key{}, err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return entities.Key{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	user, exist, err := helper.IsUserExist(creds, &Mongo)
	if err != nil {
		return entities.Key{}, err
	}
	if exist == false {
		return entities.Key{}, ewrapper.Wrap(env.ErrCredentialsValidation, env.ErrUserNotFound)
	}
	if user.IsBanned {
		return entities.Key{}, ewrapper.Wrap(env.ErrAccess, env.ErrValidation)
	}
	token, err := helper.GenerateRandomString()
	if err != nil {
		return entities.Key{}, err
	}
	newKey := entities.Key{
		Token:      token,
		IsAdmin:    user.Token.IsAdmin,
		Expired_at: helper.TokenExpiration(),
	}
	if err := Mongo.Update(bson.M{"_id": user.Id}, bson.M{"Token": newKey}); err != nil {
		return entities.Key{}, err
	}
	_, err = Redis.Connect()
	if err != nil {
		return entities.Key{}, err
	}
	// delete old and set new, becouse token - is key
	if err = Redis.Del(user.Token.Token); err != nil {
		return entities.Key{}, err
	}
	if err = Redis.Set(token, string(user.Id.Hex())); err != nil {
		return entities.Key{}, err
	}
	return entities.Key{
		Token:      token,
		IsAdmin:    user.Token.IsAdmin,
		Expired_at: helper.TokenExpiration(),
	}, nil
}

func (b *basicAuthService) Access(ctx context.Context, key entities.Key) (entities.Key, error) {
	_, err := Redis.Connect()
	if err != nil {
		return entities.Key{}, err
	}
	userId, err := helper.IsValidToken(&Redis, key)
	if err != nil {
		return entities.Key{}, err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return entities.Key{}, ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	user, err := Mongo.GetById(userId)
	if err != nil {
		return entities.Key{}, err
	}
	if user.IsBanned {
		return entities.Key{}, ewrapper.Wrap(env.ErrAccess, env.ErrValidation)
	}
	return key, nil
}

func (b *basicAuthService) Logout(ctx context.Context, key entities.Key) error {
	_, err := Redis.Connect()
	if err != nil {
		return err
	}
    userId, err := helper.IsValidToken(&Redis, key)
	if err != nil {
		return err
	}
	return Redis.Del(userId)
}

func (b *basicAuthService) UserRegistrationAttempt(ctx context.Context, creds entities.Credentials) (err error) {
	var (
		contentType = "text/html"
		subject     = "Registration Request"
		message     = fmt.Sprintf("A new user wants to be registered.<hr> <b>Name</b>: %s<br> <b>Email address</b>: %s<br> <b>Message</b>: %v", creds.Name, creds.Email, creds.Message)
	)
	return helper.SendEmail(creds.Email, env.AdminEmail, subject, message, contentType)
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

func (b *basicAuthService) BlockUser(ctx context.Context, key entities.Key) (err error) {
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	_, err = Redis.Connect()
	if err != nil {
		return err
	}
	id, err := Redis.Get(key.Token)
	if err != nil {
		return err
	}
	err = Mongo.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"isbanned": true})
	return err
}
func (b *basicAuthService) UnblockUser(ctx context.Context, key entities.Key) (err error) {
	_, err = Redis.Connect()
	if err != nil {
		return err
	}
	id, err := Redis.Get(key.Token)
	if err != nil {
		return err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	return Mongo.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"isbanned": false})
}

func (b *basicAuthService) DropUser(ctx context.Context, key entities.Key) (err error) {
	/*_, err = Redis.Connect()
	if err != nil {
		return err
	}
	id, err := Redis.Get(key.Token)
	if err != nil {
		return err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	err = Mongo.Drop(bson.M{"_id": bson.ObjectIdHex(id)})
	if err != nil {
		return err
	}
	return Redis.Del(key.Token)*/
	return err
}

func (b *basicAuthService) UpdateUser(ctx context.Context, user entities.User, key entities.Key) (err error) {
	/*_, err = Redis.Connect()
	if err != nil {
		return err
	}
	id, err := Redis.Get(key.Token)
	if err != nil {
		return err
	}
	mgoSession, err := Mongo.Connect()
	if err != nil {
		return ewrapper.Wrap(err, env.ErrDBSession)
	}
	defer mgoSession.Close()
	// don't need password and token, make RequestUpdateUser -> Email, Name, IsBanned only 
	err = Mongo.Update(bson.M{"_id": bson.ObjectIdHex(id)}, bson.M{"user": entities.User{
	    Email: user.Email,        
	    Name:  user.Name,       
	    Password: user.Password,      
	    Token:    entities.Key{
			Token:      key.Token,
	        IsAdmin:    key.IsAdmin,  
	        Expired_at: key.Expired_at,
		},        
	    IsBanned: user.IsBanned,      
	}})
	if err != nil {
		return err
	}
	// if blocked than not send anything
	var (
		contentType = "text/html"
		subject     = "Update"
		message = fmt.Sprintf("Your access data to missio.systems has been changed.<hr><b>Actual Credentials:</b><br><b>Email:</b>%s<br><b>Name:</b>%s", user.Email, user.Name)
	)
	return helper.SendEmail(env.AdminEmail, user.Email, subject, message, contentType)*/
	return err
}

func (b *basicAuthService) SearchUsers(ctx context.Context, key entities.Key) (users []entities.User, err error) {
	// get string and search by emal and name via LIKE (regex)
	return nil, err
}