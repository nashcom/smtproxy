// smtproxy - SMTP Proxy in Go / helper routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "crypto/tls"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "strconv"
    "strings"
    "syscall"
    "time"
)

func formatStr(s string) string {
    if s == "" {
        return "[]"
    }

    return s
}

func fileExists(filename string) bool {
    _, err := os.Stat(filename)
    return err == nil
}

func isSMTP2xx(resp string) bool {
    return len(resp) >= 3 && resp[0] == '2'
}

func dashLine(width int) string {
    return strings.Repeat("-", width)
}

func sleepWithShutdownCheck(n int) bool {
    for i := 0; i < n; i++ {
        if gShutdownRequested {
            return true
        }

        time.Sleep(time.Second)
    }

    return false
}

func (m TLSMode) String() string {

    switch m {

    case TLSModeImplicit:
        return "TLS"

    case TLSModeStartTLS:
        return "STARTTLS"

    case TLSModeNone:
        return "Plain"

    default:
        return "Unknown"
    }
}

func tlsVersionString(v uint16) string {
    switch v {
    case tls.VersionTLS13:
        return "TLS1.3"
    case tls.VersionTLS12:
        return "TLS1.2"
    case tls.VersionTLS11:
        return "TLS1.1"
    case tls.VersionTLS10:
        return "TLS1.0"
    default:
        return "unknown"
    }
}

func getEnv(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}

func getEnvLogLevel(key string, fallback LogLevel) LogLevel {

    if v := os.Getenv(key); v != "" {
        level, err := ParseLogLevel(v)

        if err == nil {
            return level
        } else {
            log.Printf("ERROR: Invalid log level [%s] for environment variable %s : %v", v, key, err)
            gConfigErrors++
        }
    }

    return fallback
}

func getEnvInt64(key string, fallback int64) int64 {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil {
            return n
        } else {
            log.Printf("ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
            gConfigErrors++
        }
    }

    return fallback
}

func getEnvInt(key string, fallback int) int {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            return n
        } else {
            log.Printf("ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
            gConfigErrors++
        }
    }

    return fallback
}

func getEnvBool(key string, fallback bool) bool {
    val, exists := os.LookupEnv(key)
    if !exists || val == "" {
        return fallback
    }

    parsed, err := strconv.ParseBool(val)
    if err != nil {
        log.Printf("Warning: Invalid bool value [%s] for environment variable %s : %v", parsed, key, err)
        return fallback
    }

    return parsed
}

func formatBytes(b int64) string {

    const unit = 1024

    if b < unit {
        return fmt.Sprintf("%dB", b)
    }

    div, exp := int64(unit), 0

    for n := b / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }

    value := float64(b) / float64(div)

    return fmt.Sprintf("%.2f %cB",
        value,
        "KMGTPE"[exp],
    )
}

func parseGoVersionBuild(v string) int64 {

    if !strings.Contains(v, "go") {
        return 0
    }

    i := strings.Index(v, "go")
    v = v[i+2:]

    parts := strings.Split(v, ".")

    var major, minor, patch int64

    if len(parts) > 0 {
        major, _ = strconv.ParseInt(parts[0], 10, 64)
    }

    if len(parts) > 1 {
        minor, _ = strconv.ParseInt(parts[1], 10, 64)
    }

    if len(parts) > 2 {
        p := parts[2]

        for i := 0; i < len(p); i++ {
            if p[i] < '0' || p[i] > '9' {
                p = p[:i]
                break
            }
        }

        patch, _ = strconv.ParseInt(p, 10, 64)
    }

    return major*10000 + minor*100 + patch
}

func cleanList(list []string) []string {
    var result []string
    for _, v := range list {
        v = strings.TrimSpace(v)
        if v != "" {
            result = append(result, v)
        }
    }
    return result
}

func dumpClientHelloInfo(chi *tls.ClientHelloInfo) {

    prefix := "[" + chi.Conn.RemoteAddr().String() + "] "

    log.Printf("%s----- TLS ClientHelloInfo -----", prefix)
    log.Printf("%sClient: SNI: %s", prefix, chi.ServerName)

    log.Printf("%s; Supported Versions:", prefix)
    for _, v := range chi.SupportedVersions {
        log.Printf("%s  %s", prefix, tlsVersionString(v))
    }

    log.Printf("%sCipher Suites:", prefix)
    for _, c := range chi.CipherSuites {
        log.Printf("%s  %s (0x%04x)", prefix, tls.CipherSuiteName(c), c)
    }

    log.Printf("%sSignature Schemes:", prefix)
    for _, s := range chi.SignatureSchemes {
        log.Printf("%s  %v", prefix, s)
    }

    log.Printf("%sSupported Curves:", prefix)
    for _, c := range chi.SupportedCurves {
        log.Printf("%s  %v", prefix, c)
    }

    log.Printf("%sSupported Points:", prefix)
    for _, p := range chi.SupportedPoints {
        log.Printf("%s  %v", prefix, p)
    }
}


func isClosedNetErr(err error) bool {

    if err == nil {
        return false
    }

    if errors.Is(err, io.EOF) {
        return true
    }

    if errors.Is(err, syscall.EPIPE) {
        return true
    }

    if errors.Is(err, net.ErrClosed) {
        return true
    }

    s := err.Error()

    if strings.Contains(s, "use of closed network connection") {
        return true
    }

    if strings.Contains(s, "connection reset by peer") {
        return true
    }

    return false
}

func tlsResumeString(resumed bool) string {
    if resumed {
        return "resumed"
    }
    return "new"
}
