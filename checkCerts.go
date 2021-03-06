package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "strings"
    "time"
    "flag"
)

type Config struct {
    Urls            []string
    MMurl           string
    MMkey           string
    ExpireThreshold float64
}

var (
    config          []Config
    urls            []string
    MMurl           string
    MMkey           string
    ExpireThreshold float64
    Info            *log.Logger
    Error           *log.Logger
    Warning         *log.Logger
    outputHandle    io.Writer
    err             error
)

var verboseFlag = flag.Bool("bool", false, "Verbose Mode")

func init() {
    flag.BoolVar(verboseFlag, "v", false, "Verbose Mode")
    flag.Parse()

    if *verboseFlag == true {
        outputHandle = os.Stdout
    } else {
        outputHandle, err = os.OpenFile("/var/log/checkcert", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
        if err != nil {
            log.Fatal(err)
        }
    }

    //set output of logs to fileHandle
    log.SetOutput(outputHandle)

    Info = log.New(outputHandle,
        "Info: ",
        log.Ldate|log.Ltime)

    Error = log.New(outputHandle,
        "Error: ",
        log.Ldate|log.Ltime)

    Warning = log.New(outputHandle,
        "Warning: ",
        log.Ldate|log.Ltime)
}

func main() {

    config, err := getConfig(".config")
    if err != nil {
        Error.Println("config file not found")
    }

    for _, info := range config {
        for _, url := range info.Urls {
            checkURL(string(url), float64(info.ExpireThreshold))
        }
        MMkey = info.MMkey
        MMurl = info.MMurl
    }
    //defer to close when you're done with it
    //defer fileHandle.Close()
}

// go to the url, pull down the cert
func checkURL(url string, expire float64) {
    conn, err1 := tls.Dial("tcp", url, nil)

    if err1 != nil {
        Error.Printf("Unable to get %q - %s\n", url, err)
        return
    }
    state := conn.ConnectionState()
    defer conn.Close()
    Info.Println("---------------------")
    Info.Println("client: connected to: ", conn.RemoteAddr())

    for _, cert := range state.PeerCertificates {
        var issuer string
        var dur time.Duration
        for _, name := range cert.DNSNames {
            if !strings.Contains(url, name) {
                continue
            }
            issuer = strings.Join(cert.Issuer.Organization, ", ")
            dur = cert.NotAfter.Sub(time.Now())
            if dur.Hours()/24 < expire {
                Warning.Printf("  Certificate for %q  from %q  expires %s  (%.0f days).\n\n", name, issuer, cert.NotAfter, dur.Hours()/24)
                // TODO add logic to send mesage to Mattermost
            } else {
                Info.Printf("  Certificate for %q  from %q  expires %s  (%.0f days).\n\n", name, issuer, cert.NotAfter, dur.Hours()/24)
            }
        }

        if *verboseFlag != true {
            fmt.Print("+++ ")
        }
    }
}

func getConfig(path string) ([]Config, error) {
    file, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    if err := json.Unmarshal(file, &config); err != nil {
        Error.Fatalf("JSON unmarshalling failed: %s", err)
    }
    return config, err
}
