package storage

import (
	env "todo_SELF/auth/pkg/env"
   "fmt"
	redis "github.com/go-redis/redis"
)

type Redis struct {
	Client *redis.Client
}

func (r *Redis) Connect() (*redis.Client, error) {
	r.Client = redis.NewClient(&redis.Options{
		Addr:     "auth-redis:" + env.RedisPort,
		Password: "",
		DB:       0,
	})
	_, err := r.Client.Ping().Result()
	if err != nil {
		return nil, err
	}
	return r.Client, nil
}

// key - token, value - _id
func (r *Redis) Set(key string, value string) error {
	err := r.Client.Set(key, value, 0).Err()
	return err
}

// key - token, value - _id
func (r *Redis) Get(key string) (string, error) {
	val, err := r.Client.Get(key).Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

func (r *Redis) Del(key string) error {
	_, err := r.Client.Del(key).Result()
	return err
}

func (r *Redis) Range() {
	keys:= r.Client.Do("KEYS", "*")
	fmt.Println("___________")
	fmt.Printf("KEYS:\n%+v\n", keys)
	fmt.Println("___________")
}