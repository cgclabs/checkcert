package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {

	urls := []string{}

	urls, err := readLines("domains")
	if err != nil {
		log.Printf("Data file 'domains' not found")
	}

	for _, url := range urls {
		checkURL(string(url))
	}
}

func checkURL(url string) {
	conn, err := tls.Dial("tcp", url, nil)

	if err != nil {
		log.Printf("Unable to get %q - %s\n", url, err)
		return
	}
	state := conn.ConnectionState()
	defer conn.Close()
	fmt.Print("client: connected to: ", conn.RemoteAddr())

	for _, cert := range state.PeerCertificates {
		for _, name := range cert.DNSNames {
			if !strings.Contains(url, name) {
				continue
			}
			issuer := strings.Join(cert.Issuer.Organization, ", ")
			dur := cert.NotAfter.Sub(time.Now())
			fmt.Printf("  Certificate for %q  from %q  expires %s  (%.0f days).\n\n", name, issuer, cert.NotAfter, dur.Hours()/24)
		}
	}
}
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	fmt.Print(lines)
	return lines, scanner.Err()
}
