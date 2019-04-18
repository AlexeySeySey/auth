package helper

import (
	env "todo_SELF/auth/pkg/env"

	"gopkg.in/gomail.v2"
)

const RegistrationAcceptedMessage = `
   <h5>Your registration attempt has been accepted by Administartion!</h5><hr><p>You are welcomed!</p>
`

func SendEmail(from string, to string, subject string, message string, contentType string, ch chan error) {

	// create email
	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody(contentType, message)

	// send email
	d := gomail.NewPlainDialer(env.MailHost, env.MailPort, env.SMTPConnectionUsername, env.SMTPConnectionPassword)
	err := d.DialAndSend(m)

	if err != nil {
		ch <- err
	}

}
