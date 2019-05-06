package entities

import (
	"encoding/json"

	"todo_SELF/auth/pkg/env"
)

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
