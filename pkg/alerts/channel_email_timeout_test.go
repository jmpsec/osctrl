package alerts

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A relay that accepts the connection but never sends its banner must time
// out instead of holding the alert worker.
func TestSMTPSendTimesOutOnSilentRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	old := smtpTimeout
	smtpTimeout = 200 * time.Millisecond
	t.Cleanup(func() { smtpTimeout = old })

	start := time.Now()
	err = smtpSend(ln.Addr().String(), nil, "from@example.com", []string{"to@example.com"}, []byte("hi"))
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}
