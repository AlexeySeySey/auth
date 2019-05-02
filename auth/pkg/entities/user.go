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
	Id       bson.ObjectId `json:"id" bson:"_id"` 
	IP       string        `json:"ip" bson:"ip"`
	Email    string        `json:"email" bson:"email"` 
	Name     string        `json:"name" bson:"name"` 
	Password string        `json:"password" bson:"password"` 
	Token    Key           `json:"token" bson:"token"` 
	IsBanned bool          `json:"isbanned" bson:"isbanned"` 
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
	Email    string `json:"email" bson:"email"` 
	Password string `json:"password, omitempty" bson:"password, omitempty"` 
	Name     string `json:"name, omitempty" bson:"name, omitempty"` 
	Message  string `json:"message, omitempty" bson:"message, omitempty"` 
}

func (c Credentials) String() string {
	b, err := json.Marshal(c)
	if err != nil {
		return env.ErrInvalidType.Error()
	}
	return string(b)
}
