package helper

import (
	env "todo_SELF/auth/pkg/env"

	"gopkg.in/gomail.v2"
)

const RegistrationAcceptedMessage = `
   <h5>Your registration attempt has been accepted by Administartion!</h5><hr><p>You are welcomed!</p>
`

func SendEmail(from string, to string, subject string, message string, contentType string) error {

	// create email
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody(contentType, message)

	// send email
	err := gomail.NewPlainDialer(env.MailHost, env.MailPort, env.SMTPConnectionUsername, env.SMTPConnectionPassword).DialAndSend(m)
	return err
}
