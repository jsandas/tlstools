package ccs

import (
	"context"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/jsandas/tlstools/logger"
)

const (
	vulnerable = "yes"
	safe       = "no"
	er         = "error"
)

// change cipher suite injections
func Check(host string, port string) string {
	vuln := safe

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(host),
		nmap.WithPorts(port),
		nmap.WithScripts("./vuln/ccs/script/"),
		nmap.WithContext(ctx),
	)
	if err != nil {
		logger.Errorf("event_id=ccs_test_failed msg=%v", err)
		return er
	}

	result, _, err := scanner.Run()
	if err != nil {
		logger.Errorf("event_id=ccs_test_failed msg=%v", err)
		return er
	}

	count := len(result.Hosts[0].Ports[0].Scripts)

	if count == 0 {
		return safe
	}

	logger.Debugf("event_id=ccs_test_output output=%+v", result.Hosts[0].Ports[0].Scripts)
	// logger.Debugf("event_id=ccs_test_output output=%s", result.Hosts[0].Ports[0].Scripts[0].Output)

	output := result.Hosts[0].Ports[0].Scripts[0].Output

	if strings.Contains(output, "VULNERABLE") {
		vuln = vulnerable
		logger.Debugf("event_id=ccs_test status=%s", vuln)
	} else {
		logger.Debugf("event_id=ccs_test status=%s", safe)
	}

	return vuln
}
