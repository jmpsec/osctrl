package alerts

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// channel_email.go — SMTP email channel.
//
// Config comes from the alert_channels row (host/port/credentials/from/to),
// matching the logsinks per-row config pattern so each channel can use a
// different relay. TLS posture: port 465 = implicit TLS, otherwise
// STARTTLS when enabled (default true). The send path is abstracted
// behind smtpSend so tests can render and validate without a relay.

// EmailConfig is the typed JSON config for email channels.
type EmailConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	To       string `json:"to"`
	StartTLS bool   `json:"starttls"`
}

type emailSender struct {
	cfg EmailConfig
	// send is the delivery seam (tests substitute it).
	send func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
	now  func() time.Time
}

func buildEmail(cfg EmailConfig) (ChannelSender, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if cfg.From == "" || !strings.Contains(cfg.From, "@") {
		return nil, fmt.Errorf("valid from address is required")
	}
	recipients := emailRecipients(cfg.To)
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	return &emailSender{
		cfg:  cfg,
		send: smtpSend,
		now:  time.Now,
	}, nil
}

func (s *emailSender) Name() string { return ChannelEmail }

// Send renders and delivers the notification.
func (s *emailSender) Send(h Hit) error {
	msg := s.render(h)
	recipients := emailRecipients(s.cfg.To)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	return s.send(addr, auth, s.cfg.From, recipients, msg)
}

// render builds the RFC-5322 message (headers + body). Kept separate
// for testability.
func (s *emailSender) render(h Hit) []byte {
	subject := fmt.Sprintf("[osctrl] alert: %s", h.RuleName)
	if h.Environment != "" {
		subject += fmt.Sprintf(" (env %s)", h.Environment)
	}
	var b strings.Builder
	b.WriteString("From: " + s.cfg.From + "\r\n")
	b.WriteString("To: " + s.cfg.To + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + s.now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	fmt.Fprintf(&b, "osctrl alert: %s\r\n\r\n", h.RuleName)
	if h.Environment != "" {
		fmt.Fprintf(&b, "Environment: %s\r\n", h.Environment)
	}
	if h.NodeUUID != "" {
		fmt.Fprintf(&b, "Node:        %s\r\n", h.NodeUUID)
	}
	fmt.Fprintf(&b, "Entity:      %s\r\n", h.Entity)
	fmt.Fprintf(&b, "Matched:     %s\r\n", h.Detail)
	fmt.Fprintf(&b, "Time (UTC):  %s\r\n", s.now().UTC().Format(time.RFC3339))
	return []byte(b.String())
}

// emailRecipients parses the comma-separated recipient list.
func emailRecipients(to string) []string {
	parts := strings.Split(to, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// smtpSend is the real delivery path: dials, upgrades to TLS when
// appropriate, authenticates, and sends.
func smtpSend(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("smtp addr: %w", err)
	}
	implicitTLS := strings.HasSuffix(addr, ":465")
	conn, err := tlsOrPlainDial(addr, implicitTLS)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = client.Quit() }()
	// STARTTLS on non-465 ports when the config enables it.
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	for _, r := range to {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", r, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return nil
}

// tlsOrPlainDial dials port 465 as implicit TLS, everything else plain
// (STARTTLS upgrade happens in smtpSend).
func tlsOrPlainDial(addr string, implicitTLS bool) (net.Conn, error) {
	if implicitTLS {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	}
	return net.Dial("tcp", addr)
}
