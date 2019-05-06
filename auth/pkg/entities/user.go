package entities

import (
	"encoding/json"

	"gopkg.in/mgo.v2/bson"
	
	"todo_SELF/auth/pkg/env"
)

type User struct {
	Id       bson.ObjectId `json:"id, omitempty" bson:"_id"`
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

