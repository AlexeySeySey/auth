package entities

import (
	"encoding/json"

	"todo_SELF/auth/pkg/env"
)

type Key struct {
	Token      string `json:"token" bson:"token"`
	IsAdmin    bool   `json:"isadmin" bson:"isadmin"`
	Expired_at string `json:"expired_at" bson:"expired_at"`
}

func (k Key) String() string {
	b, err := json.Marshal(k)
	if err != nil {
		return env.ErrInvalidType.Error()
	}
	return string(b)
}
