package main

import (
	"flag"
	"fmt"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/scanner"
	"github.com/jsandas/tlstools/pkg/utils"
	"gopkg.in/yaml.v2"
)

func main() {
	scanHost := flag.String("host", "", "hostname/ip address to scan")
	scanPort := flag.String("port", "443", "port to scan (default: 443")
	flag.Parse()

	logger.LogLevel = "CRITICAL"

	if !utils.ValidHost(*scanHost) || !utils.ValidPort(*scanPort) {
		fmt.Printf(" invalid host or port provided: host=%s port=%s", *scanHost, *scanPort)
		return
	}

	if !utils.CanConnect(*scanHost, *scanPort) {
		fmt.Printf(" host unreachable: %s:%s", *scanHost, *scanPort)
		return
	}

	scanCert(*scanHost, *scanPort)

	scanConfig(*scanHost, *scanPort)
}

func scanCert(host string, port string) {
	var results scanner.CertificateData

	results.ScanCertificate(host, port)

	yamlData, _ := yaml.Marshal(&results)

	fmt.Printf(string(yamlData))
}

func scanConfig(host string, port string) {
	var results scanner.ConfigurationData

	results.ScanConfiguration(host, port)

	yamlData, _ := yaml.Marshal(&results)

	fmt.Printf(string(yamlData))
}
