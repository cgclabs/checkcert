package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

type Config struct {
	Urls             []string
	MMurl            string
	MMkey            string
	ExpireThreshhold float64
}

var config []Config
var urls []string
var MMurl string
var MMkey string
var ExpireThreshhold float64

func main() {

	config, err := getConfig(".config")
	if err != nil {
		log.Printf("config file not found")
	}

	for _, info := range config {
		for _, url := range info.Urls {
			checkURL(string(url), float64(info.ExpireThreshhold))
		}
		MMkey = info.MMkey
		MMurl = info.MMurl
	}
}

// go to the url, pull down teh cert
func checkURL(url string, expire float64) {
	conn, err := tls.Dial("tcp", url, nil)

	if err != nil {
		log.Printf("Unable to get %q - %s\n", url, err)
		return
	}
	state := conn.ConnectionState()
	defer conn.Close()
	fmt.Print("---------------------")
	fmt.Print("client: connected to: ", conn.RemoteAddr())

	for _, cert := range state.PeerCertificates {
		var issuer string
		var dur time.Duration
		for _, name := range cert.DNSNames {
			if !strings.Contains(url, name) {
				continue
			}
			issuer = strings.Join(cert.Issuer.Organization, ", ")
			dur = cert.NotAfter.Sub(time.Now())
			fmt.Printf("  Certificate for %q  from %q  expires %s  (%.0f days).\n\n", name, issuer, cert.NotAfter, dur.Hours()/24)
		}
		fmt.Print("+++ ")
		if dur.Hours()/24 < expire {
			fmt.Print(issuer, "\n\n")
		}
	}
}

//
func getConfig(path string) ([]Config, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("JSON unmarshalling failed: %s", err)
	}
	return config, err
}
