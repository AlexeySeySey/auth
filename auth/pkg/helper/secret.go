package helper

import (
	"math/rand"
	"time"
)

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	TokenLength = 30
	TimeFormat  = "2006-01-02 15:04:05"
)

func GenerateRandomString() (string, error) {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, TokenLength)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b), nil
}

func TokenExpiration() string {
	return time.Now().Add(8765 * time.Hour).Format(TimeFormat)
}
