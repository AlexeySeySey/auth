package entities

import (
	"encoding/json"

	"gopkg.in/mgo.v2/bson"

	"todo_SELF/auth/pkg/env"
)

type Key struct {
	Token      string `json:"token" bson:"token"`
	IsAdmin    bool   `json:"isadmin" bson:"isadmin"`
	Expired_at string `json:"expired_at" bson:"expired_at"`
}

// user in storage
type User struct {
	Id       bson.ObjectId `bson:"_id"`
	Email    string        `bson:"email"`
	Name     string        `bson:"name"`
	Password string        `bspn:"password"`
	Token    Key           `bson:"token"`
}

func (u User) String() string {
	b, err := json.Marshal(u)
	if err != nil {
		return env.ErrInvalidType.Error()
	}
	return string(b)
}

// user credentials passed, to get token
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password, omitempty"`
	Name     string `json:"name, omitempty"`
	Message  string `json:"message, omitempty"`
}

func (c Credentials) String() string {
	b, err := json.Marshal(c)
	if err != nil {
		return env.ErrInvalidType.Error()
	}
	return string(b)
}
