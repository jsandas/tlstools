package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	color "github.com/TwiN/go-color"
	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/scanner"
	"github.com/jsandas/tlstools/pkg/utils"
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

	printCertResults(results)
}

func scanConfig(host string, port string) {
	var results scanner.ConfigurationData

	results.ScanConfiguration(host, port)

	printConfigResults(results)
}

func printCertResults(results scanner.CertificateData) {
	var i int
	fmt.Print(color.Ize(color.Green, "Host:"))
	fmt.Println(color.Ize(color.Cyan, " "+results.HostName))
	fmt.Print(color.Ize(color.Green, "Chain Trusted:"))
	fmt.Println(color.Ize(color.Cyan, " "+fmt.Sprintf("%v", results.ChainTrusted)))
	fmt.Println(color.Ize(color.Green, "Certificates:"))
	for _, cert := range results.Certificates {
		i = i + 1
		fmt.Println(color.Ize(color.Green, "  Certificate "+strconv.Itoa(i)+":"))
		fmt.Println(color.Ize(color.Green, "    Subject:"))
		fmt.Print(color.Ize(color.Green, "      Common Name:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.CommonName))
		fmt.Print(color.Ize(color.Green, "      Locality:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.LocalityName))
		fmt.Print(color.Ize(color.Green, "      Province:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.StateOrProvinceName))
		fmt.Print(color.Ize(color.Green, "      Country:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.CountryName))
		fmt.Print(color.Ize(color.Green, "      Org Unit:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.OrganizationName))
		fmt.Print(color.Ize(color.Green, "      Org Unit Name:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Subject.OrganizationalUnitName))

		fmt.Print(color.Ize(color.Green, "    Issuer:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.Issuer.CommonName))
		fmt.Print(color.Ize(color.Green, "    Key Size:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.KeyType))
		fmt.Print(color.Ize(color.Green, "    Signature Algorithm:"))
		fmt.Println(color.Ize(color.Cyan, " "+cert.SignatureAlgorithm))
	}
}

func printConfigResults(results scanner.ConfigurationData) {
	fmt.Print(color.Ize(color.Green, "OCSP Stapling:"))
	fmt.Println(color.Ize(color.Cyan, " "+fmt.Sprintf("%v", results.OCSPStapling)))
	fmt.Print(color.Ize(color.Green, "Server Header:"))
	fmt.Println(color.Ize(color.Cyan, " "+results.ServerHeader))
	fmt.Println(color.Ize(color.Green, "Protocols/Ciphers:"))
	for proto, ciphers := range results.SupportedConfig {
		fmt.Print(color.Ize(color.Green, "   "+proto+":"))
		fmt.Println(color.Ize(color.Cyan, " "+strings.Join(ciphers, " ")))
	}
}
