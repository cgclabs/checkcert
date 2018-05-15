package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"time"
)

func main() {

	var urls = []string{
		"google.com:443",
		"https://expired.badssl.com:443",
		"[wrong.host.badssl.com]:443",
		"self-signed.badssl.com:443",
		"[https://untrusted-root.badssl.com]:443",
		"[https://revoked.badssl.com]:443",
		"[https://pinning-test.badssl.com]:443",
		"[https://no-common-name.badssl.com]:443",
		"[https://no-subject.badssl.com]:443",
		"[https://incomplete-chain.badssl.com]:443",
		"[https://sha1-intermediate.badssl.com]:443",
		"[https://sha256.badssl.com]:443",
		"[https://sha384.badssl.com]:443",
		"[https://sha512.badssl.com]:443",
		"[https://1000-sans.badssl.com]:443",
		"[https://10000-sans.badssl.com]:443",
		"[https://ecc256.badssl.com]:443",
		"[https://ecc384.badssl.com]:443",
		"[https://rsa2048.badssl.com]:443",
		"[https://rsa8192.badssl.com]:443",
	}

	for _, url := range urls {
		checkURL(url)
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
			fmt.Printf("Certificate for %q from %q expires %s (%.0f days).\n", name, issuer, cert.NotAfter, dur.Hours()/24)
		}
	}
}
