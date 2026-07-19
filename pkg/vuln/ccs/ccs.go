package ccs

import (
	"context"
	"net"
	"time"

	logger "github.com/jsandas/gologger"
)

const (
	StatusNotVulnerable ProbeStatus = "no"
	StatusVulnerable    ProbeStatus = "yes"
	StatusError         ProbeStatus = "error"
)

type CCSInjection struct {
	Vulnerable string `json:"vulnerable"`
}

// Check executes the CCS injection probe with protocol fallback.
func (ccs *CCSInjection) Check(host string, port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Try TLSv1.2 (0x0303)
	res, err := ccs.probe(ctx, host, port, 0x0303)
	if err == nil {
		ccs.Vulnerable = string(res)
		return nil
	}

	// If protocol mismatch (not an error, just server doesn't support it) or error, try fallback to SSLv3 (0x0300)
	// For now, we treat any error from probe as a reason to fallback, 
	// but we might want to distinguish between "connection refused" and "protocol mismatch".
	// In this implementation, we retry on any error to be thorough.
	logger.Warnf("event_id=ccs_test_fallback msg=retrying with SSLv3 error=%v", err)
	res, err = ccs.probe(ctx, host, port, 0x0300)
	if err == nil {
		ccs.Vulnerable = string(res)
		return nil
	}

	// If both fail, it's an error
	ccs.Vulnerable = string(StatusError)
	return err
}

func (ccs *CCSInjection) probe(ctx context.Context, host, port string, version uint16) (ProbeStatus, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return StatusError, err
	}
	defer conn.Close()

	// Set deadline for the probe
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	vulnerable, status, err := probeVersion(conn, version)
	if err != nil {
		return StatusError, err
	}

	if status == ProbeStatusNotVulnerable {
		return StatusNotVulnerable, nil
	}
	if status == ProbeStatusError {
		return StatusError, nil
	}

	if vulnerable {
		return StatusVulnerable, nil
	}

	return StatusNotVulnerable, nil
}
