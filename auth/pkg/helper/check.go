package helper

import (
	"strings"
	"time"

	entities "todo_SELF/auth/pkg/entities"
	env "todo_SELF/auth/pkg/env"
	db "todo_SELF/auth/pkg/storage"

	"gopkg.in/mgo.v2/bson"

	ewrapper "github.com/pkg/errors"
)

func IsUserExist(creds entities.Credentials, Mongo *db.Mongo) (user entities.User, isAdmin bool, err error) {
	if creds.Password == "" {
		isAdmin = false
		user, err = Mongo.Search(bson.M{
			"email": creds.Email,
		})
		if err != nil {
			return user, isAdmin, ewrapper.Wrap(err, env.ErrUserNotFound)
		}
	} else {
		isAdmin = true
		user, err = Mongo.Search(bson.M{
			"email":    creds.Email,
			"password": creds.Password,
		})
		if err != nil {
			return user, false, ewrapper.Wrap(err, env.ErrUserNotFound)
		}
	}
	return user, isAdmin, nil
}

func IsValidCreds(creds entities.Credentials) error {
	if (creds.Email == "") || (strings.Contains(creds.Email, "@") == false) {
		return ewrapper.Wrap(env.ErrCredentialsValidation, env.ErrValidation)
	}
	if creds.Password != "" {
		if len(creds.Password) < 6 {
			return ewrapper.Wrap(env.ErrCredentialsValidation, env.ErrValidation)
		}
	}
	return nil
}

func IsValidToken(Redis *db.Redis, key entities.Key) (string, error) {
	// check length
	if len(key.Token) < TokenLength {
		return "", ewrapper.Wrap(env.ErrInvalidToken, env.ErrValidation)
	}

	// check storage
	userId, err := Redis.Get(key.Token)
	if err != nil {
		return "", err
	}

	// check if expired
	isNotExpired, err := CompareTimes(key.Expired_at, time.Now().Format(TimeFormat))
	if err != nil {
		return "", err
	}

	if !isNotExpired {
		return "", ewrapper.Wrap(env.ErrTokenExpired, env.ErrValidation)
	}

	return userId, nil
}
