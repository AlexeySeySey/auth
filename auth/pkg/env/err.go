package env

import "errors"

// errors
var (
	ErrInvalidType           = errors.New("UNSUPPORTED VALUE TYPE")
	ErrUserAlreadyExist      = errors.New("USER ALREADY REGISTERED")
	ErrCredentialsValidation = errors.New("INVALID CREDENTIALS")
	ErrInvalidToken          = errors.New("INVALID TOKEN PASSED")
	ErrTokenExpired          = errors.New("TOKEN EXPIRED")
	ErrPermission            = errors.New("PERMISSION DENIED")
)

// wrappers
var (
	ErrDBSession    = "STARTING DB SESSION FAILED"
	ErrUserNotFound = "USER NOT FOUND"
	ErrRegister     = "REGISTER"
	ErrValidation   = "VALIDATION"
)
