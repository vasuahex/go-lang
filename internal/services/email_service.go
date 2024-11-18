package services

import (
    "fmt"
    "net/smtp"
)

type EmailService interface {
    SendVerificationEmail(email, token string) error
}

type SMTPEmailService struct {
    host     string
    port     int
    username string
    password string
    from     string
}

func NewSMTPEmailService(host string, port int, username, password, from string) *SMTPEmailService {
    return &SMTPEmailService{
        host:     host,
        port:     port,
        username: username,
        password: password,
        from:     from,
    }
}

func (s *SMTPEmailService) SendVerificationEmail(email, token string) error {
    auth := smtp.PlainAuth("", s.username, s.password, s.host)
    to := []string{email}

    verificationLink := fmt.Sprintf("http://your-domain.com/verify-email?token=%s", token)
    message := []byte(fmt.Sprintf(`To: %s
Subject: Verify Your Email
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<h2>Welcome to Our Platform!</h2>
<p>Please click the link below to verify your email address:</p>
<p><a href="%s">Verify Email</a></p>
<p>This link will expire in 24 hours.</p>
</body>
</html>
`, email, verificationLink))

    return smtp.SendMail(
        fmt.Sprintf("%s:%d", s.host, s.port),
        auth,
        s.from,
        to,
        message,
    )
}