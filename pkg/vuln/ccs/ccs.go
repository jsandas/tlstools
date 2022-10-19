package ccs

import (
	"context"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v2"
	logger "github.com/jsandas/gologger"
)

const (
	notVulnerable = "no"
	vulnerable    = "yes"
	testFailed    = "error"
)

type CCSInjection struct {
	Vulnerable string `json:"vulnerable"`
}

// change cipher suite injections
func (ccs *CCSInjection) Check(host string, port string) error {
	// spath is the location of weakkeys binaries
	// these are copied there during the docker build
	p, _ := os.Executable()
	spath := path.Dir(p) + "/../resources/nmap"

	// override spath if running go test
	// or go run
	cwd, _ := os.Getwd()
	_, dir := path.Split(cwd)
	if dir == "ccs" {
		spath = "../../../resources/nmap"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(host),
		nmap.WithPorts(port),
		nmap.WithScripts(spath+"/ssl-ccs-injection.nse"),
		nmap.WithContext(ctx),
	)
	if err != nil {
		logger.Errorf("event_id=ccs_test_failed msg=%v", err)
		ccs.Vulnerable = testFailed
		return err
	}

	result, _, err := scanner.Run()
	if err != nil {
		logger.Errorf("event_id=ccs_test_failed msg=%v", err)
		ccs.Vulnerable = testFailed
		return err
	}

	count := len(result.Hosts[0].Ports[0].Scripts)

	if count == 0 {
		logger.Debugf("event_id=ccs_test_completed result=%s", notVulnerable)
		ccs.Vulnerable = notVulnerable
		return nil
	}

	logger.Debugf("event_id=ccs_test_output output=%+v", result.Hosts[0].Ports[0].Scripts)
	// logger.Debugf("event_id=ccs_test_output output=%s", result.Hosts[0].Ports[0].Scripts[0].Output)

	output := result.Hosts[0].Ports[0].Scripts[0].Output

	if strings.Contains(output, "VULNERABLE") {
		logger.Debugf("event_id=ccs_test_completed result=%s", vulnerable)
		ccs.Vulnerable = vulnerable
	} else {
		logger.Debugf("event_id=ccs_test_completed results=%s", notVulnerable)
	}

	return nil
}
