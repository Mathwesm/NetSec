// Run a bounded HTTP probe from a separate Windows container network compartment.
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "time"
)

func main() {
    if len(os.Args) != 3 || net.ParseIP(os.Args[1]) == nil {
        os.Exit(2)
    }
    client := &http.Client{Timeout: 3 * time.Second,
        Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
    response, err := client.Get("http://" + net.JoinHostPort(os.Args[1], os.Args[2]) + "/")
    if err != nil {
        fmt.Println(`{"connected":false}`)
        return
    }
    defer response.Body.Close()
    body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
    if err != nil { os.Exit(3) }
    result := map[string]any{"connected": response.StatusCode == http.StatusOK, "body": string(body)}
    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { os.Exit(4) }
}
