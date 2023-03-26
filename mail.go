package auth

import (
	"net/smtp"
)

// sendEmail sends an email to an user.
func sendEmail(to, subject, msg string) error {
	body := "To: " + to + "\r\nSubject: " +
		subject + "\r\n\r\n" + msg

	auth := smtp.PlainAuth("", C.AuthEmail, C.AuthPasswd, C.SMTPServer)

	err := smtp.SendMail(C.SMTPServer+":"+C.SMTPPort,
		auth, C.AuthEmail, []string{to}, []byte(body))
	if err != nil {
		return err
	}

	return nil
}
