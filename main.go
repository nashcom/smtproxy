package main

import (
    "bufio"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "strconv"
    "strings"
    "sync/atomic"
    "syscall"
    "time"
    "errors"
)


type LogLevel int
type TLSMode  int
type RoutingMode int

// Global counters

var gSessionCounter   uint64
var gSessionError     uint64
var gActiveConnections int64
var gTotalConnections  int64

// Global variables

var gLogLevel            LogLevel
var gLogHandshakeLevel   LogLevel
var gShutdownRequested   bool
var gMaxShutdownSeconds  int
var gMetricListnerAddr   string
var gCertFile            string
var gKeyFile             string
var gCertFile2           string
var gKeyFile2            string

var gCertUpdCheckSec int

var gCertificates atomic.Value // Global CertStore

const (
    TLSModeNone TLSMode = iota
    TLSModeImplicit
    TLSModeStartTLS
)

const (
    LOG_NONE LogLevel = iota
    LOG_ERROR
    LOG_INFO
    LOG_VERBOSE
    LOG_DEBUG
)

const (
    RoutingModeLocalFirst RoutingMode = iota
    RoutingModeFailover
    RoutingModeLoadBalance
)

type SmtpProxyCfg struct {
    ListenAddr            string
    TLSListenAddr         string
    TrustStoreFile        string
    RoutingMode           RoutingMode

    LocalUpstreams        []string
    RemoteUpstreams       []string
    ServerTLSConfig       *tls.Config
    RequireTLS            bool
    ClientTLS13Only       bool
    UpstreamTLS13Only     bool
    UpstreamStartTLS      bool
    UpstreamImplicitTLS   bool
    UpstreamRequireTLS    bool
    SendXCLIENT           bool
    InsecureSkipVerify    bool
    TrustedRoots          *x509.CertPool
    UpstreamMinTLSVersion uint16
    ClientTimeout         time.Duration
    counter               uint64
    MaxConnections        int64
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


func (m RoutingMode) String() string {

    switch m {

    case RoutingModeLocalFirst:
        return "local-first"

    case RoutingModeFailover:
        return "failover"

    case RoutingModeLoadBalance:
        return "loadbalance"

    default:
        return "unknown"
    }
}


func (l LogLevel) String() string {

    switch l {

    case LOG_NONE:
        return "NONE"

    case LOG_ERROR:
        return "ERROR"

    case LOG_INFO:
        return "INFO"

    case LOG_VERBOSE:
        return "VERBOSE"

    case LOG_DEBUG:
        return "DEBUG"

    default:
        return "UNKNOWN"
    }
}


func ParseLogLevel(s string) (LogLevel, error) {

    switch strings.ToLower(strings.TrimSpace(s)) {

    case "none":
        return LOG_NONE, nil

    case "error":
        return LOG_ERROR, nil

    case "info":
        return LOG_INFO, nil

    case "verbose":
        return LOG_VERBOSE, nil

    case "debug":
        return LOG_DEBUG, nil
    }

    return LOG_NONE, fmt.Errorf("Invalid log level: %s", s)
}


func ParseRoutingMode(s string) (RoutingMode, error) {

    switch strings.ToLower(strings.TrimSpace(s)) {

    case "", "local-first", "localfirst":
        return RoutingModeLocalFirst, nil

    case "failover":
        return RoutingModeFailover, nil

    case "loadbalance", "load-balance":
        return RoutingModeLoadBalance, nil
    }

    return RoutingModeLocalFirst, fmt.Errorf("Invalid routing mode: %s", s)
}


type SmtpSession struct {
    cfg *SmtpProxyCfg

    sessionStart time.Time
    sessionID    uint64

    client             net.Conn
    upstream           net.Conn
    clientReader       *bufio.Reader
    upstreamReader     *bufio.Reader

    implicitTLS        bool
    inboundTLS         bool
    tunnelMode         bool
    clientTLSResumed   bool
    upstreamTLSResumed bool
    isError            bool

    clientTLSMode      TLSMode
    upstreamTLSMode    TLSMode

    clientTLSVersion   string
    clientCipher       string
    clientCurveID      string
    clientIP           string

    upstreamIP         string
    upstreamTarget     string
    upstreamTLSVersion string
    upstreamCipher     string
    upstreamCurveID    string

    sessionError       string
    responseLines      []string
    countHelo          int

    bytesClientToUpstream int64
    bytesUpstreamToClient int64
}


var (
    smtpCommand_EHLO                = "EHLO %s\r\n"
    smtpCommand_STARTTLS            = "STARTTLS\r\n"

    smtpResponse_GreetingBytes           = []byte("220 ESMTP Service ready\r\n")
    smtpResponse_StartTLSReadyBytes      = []byte("220 Ready to start TLS\r\n")
    smtpResponse_ServiceUnavailableBytes = []byte("421 Service not available\r\n")
    smtpResponse_TLSRequiredBytes        = []byte("530 Must issue STARTTLS first\r\n")
)


const (
    version   = "0.9.4"
    copyright = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    defaultListenAddr          = ":1025"
    defaultTlsListenAddr       = ":1465"
    defaultLocalUpstream       = ":25"
    defaultMetricsAddr         = ":9100"
    defaultRemoteUpstream      = ""
    defaultRequireTLS          = true
    defaultClientTLS13Only     = false
    defaultUpstreamTLS13Only   = false
    defaultUpstreamSTARTTLS    = true
    defaultUpstreamTLS         = false
    defaultUpstreamRequireTLS  = true
    defaultSkipCertValidation  = false
    defaultSendXCLIENT         = false
    defaultCfgCheckIntervalSec = 120
    defaultClientTimeoutSec    = 120
    defaultCertFile            = "/tls/tls.crt"
    defaultKeyFile             = "/tls/tls.key"
    defaultCertFile2           = ""
    defaultKeyFile2            = ""
    defaultMaxConnections      = 1000
    defaultMaxShutdownSeconds  = 60
    defaultCertUpdCheckSec     = 300
    defaultLogLevel            = LOG_ERROR
    defaultHandshakeLogLevel   = LOG_NONE

    env_smtproxy_ListenAddr         = "SMTPROXY_LISTEN_ADDR"
    env_smtproxy_TlsListenAddr      = "SMTPROXY_TLS_LISTEN_ADDR"
    env_smtproxy_RoutingMode        = "SMTPROXY_ROUTING_MODE"
    env_smtproxy_LocalUpstreams     = "SMTPROXY_LOCAL_UPSTREAMS"
    env_smtproxy_RemoteUpstreams    = "SMTPROXY_REMOTE_UPSTREAMS"
    env_smtproxy_RequireTLS         = "SMTPROXY_REQUIRE_TLS"
    env_smtproxy_TLS13Only          = "SMTPROXY_TLS13_ONLY"
    env_smtproxy_UpstreamTLS13Only  = "SMTPROXY_UPSTREAM_TLS13_ONLY"
    env_smtproxy_UpstreamSTARTTLS   = "SMTPROXY_UPSTREAM_STARTTLS"
    env_smtproxy_UpstreamTLS        = "SMTPROXY_UPSTREAM_TLS"
    env_smtproxy_UpstreamRequireTLS = "SMTPROXY_UPSTREAM_REQUIRE_TLS"
    env_smtproxy_ServerName         = "SMTPROXY_SERVER_NAME"
    env_smtproxy_TrustedRootFile    = "SMTPROXY_TRUSTED_ROOT_FILE"
    env_smtproxy_SkipCertValidation = "SMTPROXY_SKIP_CERT_VALIDATION"
    env_smtproxy_SendXCLIENT        = "SMTPROXY_SEND_XCLIENT"
    env_smtproxy_LogLevel           = "SMTPROXY_LOGLEVEL"
    env_smtproxy_HandshakeLogLevel  = "SMTPROXY_HANDSHAKE_LOGLEVEL"
    env_smtproxy_ClientTimeoutSec   = "SMTPROXY_CLIENT_TIMEOUT"
    env_smtproxy_MaxConnections     = "SMTPROXY_MAX_CONNECTIONS"
    env_smtproxy_CertFile           = "SMTPROXY_CERT_FILE"
    env_smtproxy_KeyFile            = "SMTPROXY_KEY_FILE"
    env_smtproxy_CertFile2          = "SMTPROXY_CERT_FILE2"
    env_smtproxy_KeyFile2           = "SMTPROXY_KEY_FILE2"
    env_smtproxy_MaxShutdownSec     = "SMTPROXY_SHUTDOWN_SECONDS"
    env_smtproxy_CertUpdCheckSec    = "SMTPROXY_CERT_UPDATE_CHECK_SECONDS"
    env_smtproxy_MetricsListenAddr  = "SMTPROXY_METRICS_LISTEN_ADDR"
)


func showCfg(description, variableName, defaultValue, currentValue any) {
    fmt.Printf("%-34s  %-34s %-30v  %v\n", variableName, description, defaultValue, currentValue)
}


func showInfo(description, currentValue any) {
    fmt.Printf("%-15s:  %v\n", description, currentValue)
}


func showRuntimeInfo() {

    fmt.Printf("\nRuntime\n-------------------------\n\n")
    showInfo("Go version", runtime.Version())
    showInfo("OS",         runtime.GOOS)
    showInfo("Arch",       runtime.GOARCH)
    showInfo("CPUs",       runtime.NumCPU())
    showInfo("PID",        os.Getpid())
}


func shutdown() {

    log.Println("Shutting down ...")
    gShutdownRequested = true

    // Wait one second to make sure the signal arrived at listeners before checking if active sessions must be trained
    time.Sleep(time.Second)

    log.Printf("Waiting maximum %d seconds for shutdown ...\n", gMaxShutdownSeconds)

    for i := 0; i < gMaxShutdownSeconds; i++ {
        current := atomic.LoadInt64(&gActiveConnections)

        if current == 0 {
            break
        }

        if i%10 == 0 {
            log.Printf("Waiting for %d active connections ...\n", current)
        }
        time.Sleep(time.Second)
    }

    remaining := atomic.LoadInt64(&gActiveConnections)

    if remaining > 0 {
        log.Printf("Shutdown timeout after %s seconds, %d connections still active\n", gMaxShutdownSeconds, remaining)
    } else {
        log.Println("All connections closed")
    }

    log.Println("Shutdown completed")
}


func metricsHandler(w http.ResponseWriter, r *http.Request) {

    activeConnections := atomic.LoadInt64(&gActiveConnections)
    totalConnections  := atomic.LoadInt64(&gTotalConnections)

    w.Header().Set("Content-Type", "text/plain; version=0.0.4")

    fmt.Fprintf(w, "# HELP smtpproxy_active_connections Current active SMTP sessions\n")
    fmt.Fprintf(w, "# TYPE smtpproxy_active_connections gauge\n")
    fmt.Fprintf(w, "smtpproxy_active_connections %d\n", activeConnections)

    fmt.Fprintf(w, "# HELP smtpproxy_connections_total Total SMTP connections\n")
    fmt.Fprintf(w, "# TYPE smtpproxy_connections_total counter\n")
    fmt.Fprintf(w, "smtpproxy_connections_total %d\n", totalConnections)
}


func startMetricsListener(addr string) {

    metricsEndpoint := "/metrics"

    mux := http.NewServeMux()
    mux.HandleFunc(metricsEndpoint, metricsHandler)

    go func() {
        log.Printf("Listening at %-8s   on [%s]", metricsEndpoint, addr)

        err := http.ListenAndServe(addr, mux)
        if err != nil {
            log.Println("Metrics listener stopped:", err)
        }
    }()
}


func reloadCertificates() error {

    certs, err := loadCertificates()
    if err != nil {
        return err
    }

    gCertificates.Store(certs)

    time.Sleep(time.Second)

    log.Printf("TLS certificates reloaded (%d certs)", len(certs))

    return nil
}


func handleSignals() {

    sigChan := make(chan os.Signal, 1)

    signal.Notify(sigChan,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGHUP,
    )

    for {
        sig := <-sigChan

        switch sig {

        case syscall.SIGHUP:
            log.Printf("SIGHUP received - Reloading certificates")
            reloadCertificates()

        case syscall.SIGINT, syscall.SIGTERM:
            log.Printf("Shutdown signal received: %v", sig)
            shutdown()
            os.Exit(0)
        }
    }
}


func main() {

    var printVersion   = flag.Bool("version", false, "print version")
    var showGoVersion = flag.Bool("goversion", false, "show the go runtime version")

    flag.Parse()

    if *printVersion {
        fmt.Printf("%s", version)
        return
    }

    fmt.Printf("\n")

    if *showGoVersion {
        showRuntimeInfo()
        return
    }

    go handleSignals()

    listenAddr          := getEnv(env_smtproxy_ListenAddr,    defaultListenAddr)
    tlsListenAddr       := getEnv(env_smtproxy_TlsListenAddr, defaultTlsListenAddr)
    trustStoreFile      := strings.ToLower(getEnv(env_smtproxy_TrustedRootFile, ""))

    localUpstreams      := strings.Split (getEnv(env_smtproxy_LocalUpstreams,  defaultLocalUpstream), ",")
    remoteUpstreams     := strings.Split (getEnv(env_smtproxy_RemoteUpstreams, defaultRemoteUpstream), ",")

    requireTLS          := getEnvBool(env_smtproxy_RequireTLS,         defaultRequireTLS)
    upstreamStartTLS    := getEnvBool(env_smtproxy_UpstreamSTARTTLS,   defaultUpstreamSTARTTLS)
    upstreamImplicitTLS := getEnvBool(env_smtproxy_UpstreamTLS,        defaultUpstreamTLS)
    upstreamRequireTLS  := getEnvBool(env_smtproxy_UpstreamRequireTLS, defaultUpstreamRequireTLS)
    clientTLS13Only     := getEnvBool(env_smtproxy_TLS13Only,          defaultClientTLS13Only)
    upstreamTLS13Only   := getEnvBool(env_smtproxy_UpstreamTLS13Only,  defaultUpstreamTLS13Only)
    skipCertValidation  := getEnvBool(env_smtproxy_SkipCertValidation, defaultSkipCertValidation)
    sendXCLIENT         := getEnvBool(env_smtproxy_SendXCLIENT,        defaultSendXCLIENT)
    clientTimeoutSec    := getEnvInt (env_smtproxy_ClientTimeoutSec,   defaultClientTimeoutSec)
    maxConnections      := getEnvInt64(env_smtproxy_MaxConnections,    defaultMaxConnections)

    gMaxShutdownSeconds = getEnvInt (env_smtproxy_MaxShutdownSec,      defaultMaxShutdownSeconds)
    gCertUpdCheckSec    = getEnvInt (env_smtproxy_CertUpdCheckSec,     defaultCertUpdCheckSec)

    gLogLevel           = LogLevel  (getEnvInt(env_smtproxy_LogLevel,          int(defaultLogLevel)))
    gLogHandshakeLevel  = LogLevel  (getEnvInt(env_smtproxy_HandshakeLogLevel, int(defaultHandshakeLogLevel)))
    gMetricListnerAddr  = getEnv    (env_smtproxy_MetricsListenAddr,           defaultMetricsAddr)

    gCertFile  = getEnv(env_smtproxy_CertFile,  defaultCertFile)
    gKeyFile   = getEnv(env_smtproxy_KeyFile,   defaultKeyFile)
    gCertFile2 = getEnv(env_smtproxy_CertFile2, defaultCertFile2)
    gKeyFile2  = getEnv(env_smtproxy_KeyFile2,  defaultKeyFile2)

    routingMode, ErrRoutingMode := ParseRoutingMode(getEnv(env_smtproxy_RoutingMode, ""))

    if ErrRoutingMode != nil {
        log.Fatalf("Invalid routing mode in configuration (%s) Valid options [%s|%s|%s] : %v",
            env_smtproxy_RoutingMode, RoutingModeLocalFirst, RoutingModeFailover, RoutingModeLoadBalance, ErrRoutingMode)
    }

    certs, err := loadCertificates()
    if err != nil {
        log.Fatal(err)
    }

    gCertificates.Store(certs)

    var upstreamMinTLSVersion uint16 = tls.VersionTLS12
    var clientMinTLSVersion   uint16 = tls.VersionTLS12

    // Set minimum TLS version

    if clientTLS13Only {
        clientMinTLSVersion = tls.VersionTLS13
    }

    if upstreamTLS13Only {
        upstreamMinTLSVersion = tls.VersionTLS13
    }

    serverTLS := &tls.Config{
        MinVersion: clientMinTLSVersion,
        PreferServerCipherSuites: true,

        GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {

            certs := gCertificates.Load().([]tls.Certificate)

            prefix := "[" + chi.Conn.RemoteAddr().String() + "] "

            if gLogHandshakeLevel >= LOG_DEBUG {
                dumpClientHelloInfo(chi)
            }

            supportsECDSA := false

            for _, sig := range chi.SignatureSchemes {

                switch sig {

                case tls.ECDSAWithP256AndSHA256,
                     tls.ECDSAWithP384AndSHA384,
                     tls.ECDSAWithP521AndSHA512:
                     supportsECDSA = true
                }
            }

            if gLogHandshakeLevel >= LOG_INFO {

                if (supportsECDSA) {
                    log.Printf("%sClient supports ECDSA", prefix)
                } else {
                    log.Printf("%sClient supports only RSA", prefix)
                }
            }

            for i := range certs {

                cert := &certs[i]
                err := chi.SupportsCertificate(cert)

                if err != nil {

                    if gLogHandshakeLevel >= LOG_INFO {
                        log.Printf("%sCertificate %d rejected:", prefix, i)
                        log.Printf("%s  Subject: %s",   prefix, cert.Leaf.Subject)
                        log.Printf("%s  Algorithm: %s", prefix, cert.Leaf.PublicKeyAlgorithm)
                        log.Printf("%s  Reason: %v",    prefix, err)
                    }

                    continue
                }

                if gLogHandshakeLevel >= LOG_INFO {
                    log.Printf("%sCertificate %d selected:", prefix, i)
                    log.Printf("%s  Subject: %s",   prefix, cert.Leaf.Subject)
                    log.Printf("%s  Algorithm: %s", prefix, cert.Leaf.PublicKeyAlgorithm)
                }

                return cert, nil
            }

            if gLogHandshakeLevel >= LOG_ERROR {
                log.Printf("%sNo certificate matched, falling back to first", prefix)
            }

            return &certs[0], nil
        },
    }

    cfg := &SmtpProxyCfg{
        ListenAddr:            listenAddr,
        TLSListenAddr:         tlsListenAddr,
        RoutingMode:           routingMode,
        LocalUpstreams:        cleanList(localUpstreams),
        RemoteUpstreams:       cleanList(remoteUpstreams),
        TrustStoreFile:        trustStoreFile,
        ServerTLSConfig:       serverTLS,
        RequireTLS:            requireTLS,
        ClientTLS13Only:       clientTLS13Only,
        UpstreamStartTLS:      upstreamStartTLS,
        UpstreamImplicitTLS:   upstreamImplicitTLS,
        UpstreamTLS13Only:     upstreamTLS13Only,
        UpstreamRequireTLS:    upstreamRequireTLS,
        InsecureSkipVerify:    skipCertValidation,
        UpstreamMinTLSVersion: upstreamMinTLSVersion,
        MaxConnections:        maxConnections,
        SendXCLIENT:           sendXCLIENT,
        ClientTimeout:         time.Duration(clientTimeoutSec) * time.Second,
    }

    if "" == cfg.TrustStoreFile {
        cfg.TrustedRoots, err = x509.SystemCertPool()

        if nil != err {
            log.Fatal("Failed to system trusted roots:", err)
        }

    } else {

        if !fileExists (cfg.TrustStoreFile) {
            log.Fatalf("Trusted root file does not exist: %s (%s)", cfg.TrustStoreFile, env_smtproxy_TrustedRootFile)
        }

        cfg.TrustedRoots = x509.NewCertPool()
        ca, err := os.ReadFile(cfg.TrustStoreFile)

        if nil == err {
            cfg.TrustedRoots.AppendCertsFromPEM(ca)
        } else {
            log.Fatal("Failed to system trusted roots:", err)
        }
    }

    fmt.Printf("\n")
    fmt.Printf("SMTP Proxy V%s\n", version)
    fmt.Printf("%s\n\n", dashLine (25))
    fmt.Printf("%s\n\n\n", copyright)
    showCfg("Description", "Variable", "Default", "Current")
    fmt.Printf("%s\n", dashLine (140))

    showCfg("STARTTLS listen address", env_smtproxy_ListenAddr,            formatStr(defaultListenAddr),     cfg.ListenAddr)
    showCfg("TLS      listen address", env_smtproxy_TlsListenAddr,         formatStr(defaultTlsListenAddr),  cfg.TLSListenAddr)
    showCfg("Metrics  listen address", env_smtproxy_MetricsListenAddr,     formatStr(defaultMetricsAddr),    gMetricListnerAddr)

    showCfg("Routing mode",            env_smtproxy_RoutingMode,           RoutingModeLocalFirst,            cfg.RoutingMode)
    showCfg("Local  upstreams",        env_smtproxy_LocalUpstreams,        formatStr(defaultLocalUpstream),  cfg.LocalUpstreams)
    showCfg("Remote upstreams",        env_smtproxy_RemoteUpstreams,       formatStr(defaultRemoteUpstream), cfg.RemoteUpstreams)
    showCfg("Require TLS",             env_smtproxy_RequireTLS,            defaultRequireTLS,                cfg.RequireTLS)
    showCfg("Upstream use STARTTLS",   env_smtproxy_UpstreamSTARTTLS,      defaultUpstreamSTARTTLS,          cfg.UpstreamStartTLS)
    showCfg("Upstream requires TLS",   env_smtproxy_UpstreamRequireTLS,    defaultUpstreamRequireTLS,        cfg.UpstreamRequireTLS)
    showCfg("Upstream implicit TLS",   env_smtproxy_UpstreamTLS,           defaultUpstreamTLS,               cfg.UpstreamImplicitTLS)
    showCfg("TLS13 only",              env_smtproxy_TLS13Only,             defaultClientTLS13Only,           cfg.ClientTLS13Only)
    showCfg("Upstream TLS13 only",     env_smtproxy_UpstreamTLS13Only,     defaultUpstreamTLS13Only,         cfg.UpstreamTLS13Only)
    showCfg("Skip cert validation",    env_smtproxy_SkipCertValidation,    defaultSkipCertValidation,        cfg.InsecureSkipVerify)
    showCfg("XCLIENT to signal IP",    env_smtproxy_SendXCLIENT,           defaultSendXCLIENT,               cfg.SendXCLIENT)
    showCfg("Maximum sessions",        env_smtproxy_MaxConnections,        defaultMaxConnections,            cfg.MaxConnections)
    showCfg("Trusted root file",       env_smtproxy_TrustedRootFile,       "<System trust stor>",            formatStr(cfg.TrustStoreFile))
    showCfg("Certificate file",        env_smtproxy_CertFile,              formatStr(defaultCertFile),       formatStr(gCertFile))
    showCfg("Private key file",        env_smtproxy_KeyFile,               formatStr(defaultKeyFile),        formatStr(gKeyFile))
    showCfg("Certificate file2",       env_smtproxy_CertFile2,             formatStr(defaultCertFile2),      formatStr(gCertFile2))
    showCfg("Private key file2",       env_smtproxy_KeyFile2,              formatStr(defaultKeyFile2),       formatStr(gKeyFile2))
    showCfg("Client timeout (sec)",    env_smtproxy_ClientTimeoutSec,      defaultClientTimeoutSec,          cfg.ClientTimeout)
    showCfg("Max shutdown time (sec)", env_smtproxy_MaxShutdownSec,        defaultMaxShutdownSeconds,        gMaxShutdownSeconds)
    showCfg("Cert Update Check (sec)", env_smtproxy_CertUpdCheckSec,       defaultCertUpdCheckSec,           gCertUpdCheckSec)
    showCfg("Log level",               env_smtproxy_LogLevel,              defaultLogLevel,                  gLogLevel)
    showCfg("Handshake Log level",     env_smtproxy_HandshakeLogLevel,     defaultHandshakeLogLevel,         gLogHandshakeLevel)

    // LATER: showCfg("Server name",             env_smtproxy_ServerName,            formatStr(""),                    "")

    logLevelValues := fmt.Sprintf("%d=%s %d=%s %d=%s %d=%s %d=%s",
            LOG_NONE,    LOG_NONE,
            LOG_ERROR,   LOG_ERROR,
            LOG_INFO,    LOG_INFO,
            LOG_VERBOSE, LOG_VERBOSE,
            LOG_DEBUG,   LOG_DEBUG)

    routingModeValues := fmt.Sprintf("[%s|%s|%s]", RoutingModeLocalFirst, RoutingModeFailover, RoutingModeLoadBalance)

    fmt.Printf("\n")
    fmt.Printf("Routing mode values:\n");
    fmt.Printf("  %s\n", routingModeValues);
    fmt.Printf("\nLog level values:\n");
    fmt.Printf("  %s\n", logLevelValues);
    fmt.Printf("\n");

    showRuntimeInfo()
    showInfo("Trust Store", len(cfg.TrustedRoots.Subjects()))
    fmt.Printf("\n");

    if  cfg.UpstreamImplicitTLS && cfg.UpstreamRequireTLS {
        fmt.Printf("\nWarning: Upstream STARTTLS and implicit TLS cannot be enabled at the same time!\n\n")
    }

    go watchCertificateFiles()

    log.Printf("Starting listeners ...\n\n")

    // Plain SMTP listener (STARTTLS capable)
    if cfg.ListenAddr != "" {
        go func() {
            listener, err := net.Listen("tcp", cfg.ListenAddr)
            if err != nil {
                log.Fatal(err)
            }

            log.Printf("Listening with STARTTLS on [%s]", cfg.ListenAddr)

            for {
                conn, err := listener.Accept()

                if err != nil {
                    log.Println(err)
                    continue
                }

                if errors.Is(err, net.ErrClosed) {
                    log.Printf("STARTTLS listener closed")
                    break
                }

                if gShutdownRequested {
                    log.Printf("STARTTLS listener shutdown")
                    conn.Close()
                    break
                }

                CurrentActiveConnections := atomic.LoadInt64(&gActiveConnections)
                if  CurrentActiveConnections >= int64(cfg.MaxConnections) {
                    log.Printf("Connection limit reached (%d), rejecting [%s]", cfg.MaxConnections, conn.RemoteAddr())
                    conn.Close()
                    continue
                }

                go handleConnection(conn, cfg, false)
            }
        }()
    }

    // Implicit TLS listener (SMTPS)
    if cfg.TLSListenAddr != "" {
        go func() {
            listener, err := tls.Listen("tcp", cfg.TLSListenAddr, cfg.ServerTLSConfig)
            if err != nil {
                log.Fatal(err)
            }

            log.Printf("Listening with SMTP TLS on [%s]", cfg.TLSListenAddr)

            for {
                conn, err := listener.Accept()
                if err != nil {
                    log.Println(err)
                    continue
                }

                if errors.Is(err, net.ErrClosed) {
                    log.Printf("TLS listener closed")
                    break
                }

                if gShutdownRequested {
                    log.Printf("TLS listener shutdown")
                    conn.Close()
                    break
                }

                CurrentActiveConnections := atomic.LoadInt64(&gActiveConnections)
                if  CurrentActiveConnections >= int64(cfg.MaxConnections) {
                    log.Printf("Connection limit reached (%d), rejecting [%s]", cfg.MaxConnections, conn.RemoteAddr())
                    conn.Close()
                    continue
                }

                if gLogLevel >= LOG_DEBUG {
                    log.Printf("Accepted new client from [%s] (Current Connections: %d)", conn.RemoteAddr(), CurrentActiveConnections)
                }

                go handleConnection(conn, cfg, true)
            }
        }()
    }

    if gMetricListnerAddr != "0" && gMetricListnerAddr != "" {
        startMetricsListener(gMetricListnerAddr)
    }

    select {}
}


func loadCertificates() ([]tls.Certificate, error) {

    if !fileExists(gCertFile) {
        return nil, fmt.Errorf("certificate file does not exist: %s", gCertFile)
    }

    if !fileExists(gKeyFile) {
        return nil, fmt.Errorf("key file does not exist: %s", gKeyFile)
    }

    cert, err := tls.LoadX509KeyPair(gCertFile, gKeyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load certificate (%s/%s): %v", gCertFile, gKeyFile, err)
    }

    certs := []tls.Certificate{cert}

    if gCertFile2 != "" && gKeyFile2 != "" {

        if !fileExists(gCertFile2) {
            return nil, fmt.Errorf("certificate file does not exist: %s", gCertFile2)
        }

        if !fileExists(gKeyFile2) {
            return nil, fmt.Errorf("key file does not exist: %s", gKeyFile2)
        }

        cert2, err := tls.LoadX509KeyPair(gCertFile2, gKeyFile2)
        if err != nil {
            return nil, fmt.Errorf("failed to load second certificate (%s/%s): %v", gCertFile2, gKeyFile2, err)
        }

        certs = append(certs, cert2)

        log.Printf("Additional certificate loaded")
    }

    // Parse leaf certificates to avoid handshake parsing cost
    for i := range certs {

        leaf, err := x509.ParseCertificate(certs[i].Certificate[0])
        if err != nil {
            return nil, fmt.Errorf("failed to parse certificate: %v", err)
        }

        certs[i].Leaf = leaf
    }

    x509Certs, _ := tlsCertsToX509(certs)

    if gLogLevel >= LOG_DEBUG {
        dumpCertificateChain("Server", x509Certs, true)
    } else if gLogLevel >= LOG_VERBOSE {
        dumpCertificateChain("Server", x509Certs, false)
    }

    return certs, nil
}


func NewSmtpSession(client net.Conn, cfg *SmtpProxyCfg, implicitTLS bool) *SmtpSession {

    id := atomic.AddUint64(&gSessionCounter, 1)

    return &SmtpSession{
        cfg:          cfg,
        client:       client,
        clientReader: bufio.NewReader(client),
        implicitTLS:  implicitTLS,

        sessionID:    id,
        sessionStart: time.Now(),
    }
}


func (s *SmtpSession) logf(level LogLevel, format string, args ...any) {

    if level > gLogLevel {
        return
    }

    if level == LOG_ERROR {
        s.isError = true
        s.sessionError = fmt.Sprintf(format, args...)
    }

    log.Printf("[%08d %s] %s: "+format,
        append([]any{s.sessionID, s.clientIP, level}, args...)...)
}


func (s *SmtpSession) readClientLine() (string, error) {
    s.client.SetReadDeadline(time.Now().Add(60 * time.Second))

    line, err := s.clientReader.ReadString('\n')

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "C>  %s", strings.TrimSpace(line))
    }

    return line, err
}


func (s *SmtpSession) readUpstreamLine() (string, error) {
    s.upstream.SetReadDeadline(time.Now().Add(60 * time.Second))

    line, err := s.upstreamReader.ReadString('\n')

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "U>  %s", strings.TrimSpace(line))
    }

    return line, err
}


func (s *SmtpSession) writeClientBytes(data []byte) error {

    written, err := s.client.Write(data)
    s.bytesUpstreamToClient += int64(written)

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "C<  %s", strings.TrimSpace(string (data)))
    }

    return err
}


func (s *SmtpSession) writeUpstreamStr(data string) error {
    written, err := s.upstream.Write([]byte(data))
    s.bytesClientToUpstream += int64(written)

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "U<  %s", strings.TrimSpace(data))
    }

    return err
}


func (s *SmtpSession) connectUpstream() error {
    targets := s.cfg.selectUpstreams()

    s.logf(LOG_DEBUG, "Connect to Upstream: %v", targets)

    dialer := net.Dialer{
        Timeout: 5 * time.Second,
    }

    hostname, _ := os.Hostname()

    for _, target := range targets {

        hostOnly, _, _ := net.SplitHostPort(target)

        // ----- Implicit TLS -----

        if s.cfg.UpstreamImplicitTLS {

            tlsConn, err := tls.DialWithDialer(&dialer, "tcp", target, &tls.Config{
                ServerName:         hostOnly,
                RootCAs:            s.cfg.TrustedRoots,
                InsecureSkipVerify: s.cfg.InsecureSkipVerify,
                MinVersion:         s.cfg.UpstreamMinTLSVersion,
            })

            if err != nil {
                s.logf(LOG_ERROR, "Upstream TLS connect [%s] failed: %v", target, err)
                continue
            }

            state := tlsConn.ConnectionState()
            s.upstreamTLSVersion = tlsVersionString(state.Version)
            s.upstreamCipher     = tls.CipherSuiteName(state.CipherSuite)
            s.upstreamCurveID    = state.CurveID.String()
            s.upstreamTLSMode    = TLSModeImplicit
            s.upstreamTLSResumed = state.DidResume

            s.upstream = tlsConn
            s.upstreamReader = bufio.NewReader(tlsConn)

            _, err = s.readUpstreamLine()
            if err != nil {
                s.logf(LOG_ERROR, "Cannot read from upstream connection [%s]: %v", target, err)
                tlsConn.Close()
                continue
            }

            s.upstreamTLSMode = TLSModeStartTLS
            s.logf(LOG_INFO, "Connected to upstream TLS [%s] (%s)", target, tlsInfoString (s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamCurveID, s.upstreamTLSResumed))

            return nil
        }

        // ----- Plain Connect -----

        conn, err := dialer.Dial("tcp", target)
        if err != nil {
            s.logf(LOG_ERROR, "Cannot connect to upstream [%s] : %v", target, err)
            continue
        }

        reader := bufio.NewReader(conn)

        _, err = reader.ReadString('\n')
        if err != nil {
            s.logf(LOG_ERROR, "Cannot read from upstream [%s] : %v", target, err)
            conn.Close()
            continue
        }

        fmt.Fprintf(conn, smtpCommand_EHLO, hostname)

        supportsStartTLS := false

        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                s.logf(LOG_ERROR, "Cannot read from upstream [%s] : %v", target, err)
                conn.Close()
                goto nextTarget
            }

            if strings.Contains(strings.ToUpper(line), "STARTTLS") {
                supportsStartTLS = true
            }

            if len(line) < 4 || line[3] != '-' {
                break
            }
        }

        if s.cfg.UpstreamStartTLS && supportsStartTLS {

            fmt.Fprintf(conn, smtpCommand_STARTTLS)

            resp, err := reader.ReadString('\n')
            if err != nil || !isSMTP2xx(resp) {
                s.logf(LOG_ERROR, "Cannot unexpected status returned from upstream [%s]. Response: [%v] : %v", target, resp, err)
                conn.Close()
                goto nextTarget
            }

            tlsConn := tls.Client(conn, &tls.Config{
                ServerName:         hostOnly,
                RootCAs:            s.cfg.TrustedRoots,
                InsecureSkipVerify: s.cfg.InsecureSkipVerify,
                MinVersion:         s.cfg.UpstreamMinTLSVersion,
            })

            if err := tlsConn.Handshake(); err != nil {
                s.logf(LOG_ERROR, "Handshake to upstream [%s] failed: %v", target, err)
                tlsConn.Close()
                goto nextTarget
            }

            state := tlsConn.ConnectionState()
            s.upstreamTLSVersion = tlsVersionString(state.Version)
            s.upstreamCipher     = tls.CipherSuiteName(state.CipherSuite)
            s.upstreamCurveID    = state.CurveID.String()
            s.upstreamTLSResumed = state.DidResume

            s.upstream = tlsConn
            s.upstreamReader = bufio.NewReader(tlsConn)
            s.upstreamTLSMode = TLSModeStartTLS

            s.logf(LOG_INFO, "Connected STARTTLS upstream [%s] (%s)", target, tlsInfoString (s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamCurveID, s.upstreamTLSResumed))

            return nil
        }

        s.upstream = conn
        s.upstreamReader = reader

        s.logf(LOG_INFO, "Connected plain upstream [%s]", target)

        return nil

    nextTarget:
        continue
    }

    return fmt.Errorf("all upstreams failed")
}

func (s *SmtpSession) handleStartTLS() error {

    for s.clientReader.Buffered() > 0 {
        _, _ = s.clientReader.ReadByte()
    }

    if err := s.writeClientBytes(smtpResponse_StartTLSReadyBytes); err != nil {
        return err
    }

    tlsConn := tls.Server(s.client, s.cfg.ServerTLSConfig)

    if err := tlsConn.Handshake(); err != nil {
        return err
    }

    state := tlsConn.ConnectionState()
    s.clientTLSVersion = tlsVersionString(state.Version)
    s.clientCipher     = tls.CipherSuiteName(state.CipherSuite)
    s.clientCurveID    = state.CurveID.String()
    s.clientTLSResumed = state.DidResume

    s.client = tlsConn
    s.clientReader = bufio.NewReader(tlsConn)

    s.inboundTLS    = true
    s.clientTLSMode = TLSModeStartTLS

    s.logf(LOG_INFO, "Client STARTTLS established [%s] (%s)", s.clientIP, tlsInfoString(s.clientTLSMode, s.clientTLSVersion, s.clientCipher, s.clientCurveID, s.clientTLSResumed))

    return nil
}

func (s *SmtpSession) handleEHLO(line string) error {

    if err := s.writeUpstreamStr(line); err != nil {
        return err
    }

    s.responseLines = nil

    for {
        resp, err := s.readUpstreamLine()
        if err != nil {
            return err
        }

        s.responseLines = append(s.responseLines, resp)

        if len(resp) < 4 || resp[3] != '-' {
            break
        }
    }

    hasStartTLS := false

    for _, l := range s.responseLines {
        if strings.Contains(strings.ToUpper(l), "STARTTLS") {
            hasStartTLS = true
        }
    }

    if !hasStartTLS && !s.inboundTLS {
        last := s.responseLines[len(s.responseLines)-1]
        s.responseLines[len(s.responseLines)-1] = "250-STARTTLS\r\n"
        s.responseLines = append(s.responseLines, last)
    }

    for _, l := range s.responseLines {
        s.writeClientBytes([]byte(l))
    }

    s.countHelo++

    return nil
}


func (s *SmtpSession) startTunnel() {

    type tunnelResult struct {
        dir   string
        bytes int64
        err   error
    }

    done := make(chan tunnelResult, 2)

    // Client -> Upstream
    go func() {
        n, err := io.Copy(s.upstream, s.client)
        done <- tunnelResult{dir: "client-upstream", bytes: n, err: err}
    }()

    // Upstream -> Client
    go func() {
        n, err := io.Copy(s.client, s.upstream)
        done <- tunnelResult{dir: "upstream-client", bytes: n, err: err}
    }()

    r1 := <-done

    _ = s.client.Close()
    _ = s.upstream.Close()

    var r2 *tunnelResult

    select {
    case rr := <-done:
        r2 = &rr
    case <-time.After(2 * time.Second):
    }

    apply := func(r tunnelResult) {

        if r.dir == "client-upstream" {
            s.bytesClientToUpstream += r.bytes
        }

        if r.dir == "upstream-client" {
            s.bytesUpstreamToClient += r.bytes
        }

        if r.err != nil && !isClosedNetErr(r.err) {
            s.logf(LOG_ERROR, "%s: %v", r.dir, r.err)
        }
    }

    apply(r1)

    if r2 != nil {
        apply(*r2)
    }
}


func (s *SmtpSession) sendXCLIENT() {

    if !s.cfg.SendXCLIENT {
        return
    }

    clientIP, _, _ := net.SplitHostPort(s.client.RemoteAddr().String())

    if clientIP == "" {
        clientIP = s.client.RemoteAddr().String()
    }

    cmd := fmt.Sprintf("XCLIENT ADDR=%s TLSVERSION=%s TLSCIPHER=%s TLSCURVE=%s\r\n", clientIP, s.clientTLSVersion, s.clientCipher, s.clientCurveID)

    s.logf(LOG_VERBOSE, "Sending XCLIENT: %s", strings.TrimSpace(cmd))

    if err := s.writeUpstreamStr(cmd); err != nil {
        s.logf(LOG_ERROR, "XCLIENT failed: %v", err)
        return
    }

    resp, err := s.readUpstreamLine()
    if err != nil || !strings.HasPrefix(resp, "2") {
        s.logf(LOG_ERROR, "Upstream rejected XCLIENT: %s", resp)
    }
}

func (s *SmtpSession) run() {

    var err error

    s.clientIP, _, err = net.SplitHostPort(s.client.RemoteAddr().String())
    if err != nil {
        s.clientIP = s.client.RemoteAddr().String()
    }

    if err = s.connectUpstream(); err != nil {
        s.writeClientBytes(smtpResponse_ServiceUnavailableBytes)
        return
    }

    s.upstreamTarget = s.upstream.RemoteAddr().String()
    s.upstreamIP, _, err = net.SplitHostPort(s.upstreamTarget)
    if err != nil {
        s.upstreamIP = s.upstream.RemoteAddr().String()
    }

    defer s.upstream.Close()

    if s.implicitTLS {

        if tlsConn, ok := s.client.(*tls.Conn); ok {

            if err := tlsConn.Handshake(); err != nil {
                return
            }

            state := tlsConn.ConnectionState()
            s.clientTLSVersion = tlsVersionString(state.Version)
            s.clientCipher     = tls.CipherSuiteName(state.CipherSuite)
            s.clientCurveID    = state.CurveID.String()
            s.clientTLSResumed = state.DidResume

            s.inboundTLS    = true
            s.clientTLSMode = TLSModeImplicit // Client is already TLS connected

            s.logf(LOG_INFO, "Client implicit TLS [%s] (%s)", s.clientIP, tlsInfoString(s.clientTLSMode, s.clientTLSVersion, s.clientCipher, s.clientCurveID, s.clientTLSResumed))
        }
    }

    s.writeClientBytes(smtpResponse_GreetingBytes)

    if s.inboundTLS {
        s.sendXCLIENT()
    }

    for {

        if s.tunnelMode {
            s.startTunnel()
            return
        }

        line, err := s.readClientLine()
        if err != nil {
            return
        }

        cmd := strings.ToUpper(strings.TrimSpace(line))

        if strings.HasPrefix(cmd, "EHLO ") ||
            strings.HasPrefix(cmd, "HELO ") {

            if err := s.handleEHLO(line); err != nil {
                return
            }

            continue
        }

        if cmd == "STARTTLS" {

            if err := s.handleStartTLS(); err != nil {
                return
            }

            s.sendXCLIENT()

            continue
        }

        if s.cfg.RequireTLS && !s.inboundTLS &&
            (strings.HasPrefix(cmd, "MAIL FROM") ||
                strings.HasPrefix(cmd, "RCPT TO") ||
                cmd == "DATA") {

            s.writeClientBytes(smtpResponse_TLSRequiredBytes)
            return
        }

        if err := s.writeUpstreamStr(line); err != nil {
            return
        }

        switchToTunnel := strings.HasPrefix(cmd, "DATA")

        for {
            resp, err := s.readUpstreamLine()
            if err != nil {
                return
            }

            s.writeClientBytes([]byte(resp))

            if len(resp) < 4 || resp[3] != '-' {
                break
            }
        }

        if switchToTunnel {
            s.tunnelMode = true
        }
    }
}

func handleConnection(client net.Conn, cfg *SmtpProxyCfg, implicitTLS bool) {

    atomic.AddInt64(&gActiveConnections, 1)
    defer atomic.AddInt64(&gActiveConnections, -1)

    atomic.AddInt64(&gTotalConnections, 1)

    defer client.Close()
    session := NewSmtpSession(client, cfg, implicitTLS)
    session.run()
    session.logSessionSummary()
}


func tlsInfoString(mode TLSMode, version, cipher string, curveID string, resumed bool) string {

    if mode == TLSModeNone {
        return mode.String()
    }

    resume := "new"

    if resumed {
        resume = "resumed"
    }

    return fmt.Sprintf("%s %s %s %s %s", mode, version, cipher, curveID, resume)
}


func (s *SmtpSession) logSessionSummary() {

    duration := time.Since(s.sessionStart)
    seconds := duration.Seconds()
    var statusText string
    var mbps float64

    if seconds > 0 {
        mbps = float64(s.bytesClientToUpstream) / 1024 / 1024 / seconds
    }

    if s.isError {
        statusText = "ERROR: " + s.sessionError
        atomic.AddUint64(&gSessionError, 1)

    } else {
        statusText = "OK"
    }

    s.logf(LOG_INFO,
        "Session Summary | Duration %.2fs | C->U %s | U->C %s | Avg %.2f MB/s | Client [%s] (%s) -> Upstream [%s] (%s) Status: [%s]",
        seconds,
        formatBytes(s.bytesClientToUpstream),
        formatBytes(s.bytesUpstreamToClient),
        mbps,
        s.clientIP,
        tlsInfoString(
            s.clientTLSMode,
            s.clientTLSVersion,
            s.clientCipher,
            s.clientCurveID,
            s.clientTLSResumed,
        ),
        s.upstreamTarget,
        tlsInfoString(
            s.upstreamTLSMode,
            s.upstreamTLSVersion,
            s.upstreamCipher,
            s.upstreamCurveID,
            s.upstreamTLSResumed,
        ),
        statusText,
    )
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


func getEnvInt64(key string, fallback int64) int64 {
    if v := os.Getenv(key); v != "" {

        if n, err := strconv.ParseInt(v, 10, 64); err == nil {
            return n
        }
    }

    return fallback
}

func getEnvInt(key string, fallback int) int {
    if v := os.Getenv(key); v != "" {

        if n, err := strconv.Atoi(v); err == nil {
            return n
        }
    }

    return fallback
}


func getEnvBool(name string, def bool) bool {
    val, exists := os.LookupEnv(name)
    if !exists || val == "" {
        return def
    }

    parsed, err := strconv.ParseBool(val)
    if err != nil {
        return def
    }

    return parsed
}


func dumpCertificateChain(description string, chain []*x509.Certificate, showDetails bool) {

    // Only prints basic information from leaf only if showDetails is false 

    fmt.Printf("\n")
    fmt.Printf("---------------------------------------------------\n")

    if showDetails {
        fmt.Printf("Certificates(%d) %s\n", len(chain), description)
    } else {
        fmt.Printf("Leaf Certificate %s\n", description)
    }

    fmt.Printf("---------------------------------------------------\n")
    fmt.Printf("\n")

    for i, cert := range chain {

        if showDetails {
            fmt.Printf("----- Certificate %d -----\n\n", i)

            if i == 0 {
                showInfo("Type", "Leaf")
            } else {
                showInfo("Type", "Intermediate/CA")
            }
        }

        showInfo("Subject", cert.Subject.String())
        showInfo("Issuer", cert.Issuer.String())

        if len(cert.DNSNames) > 0 {
            showInfo("DNS SANs", strings.Join(cert.DNSNames, " "))
        }

        if len(cert.IPAddresses) > 0 {
            ips := make([]string, len(cert.IPAddresses))
            for i, ip := range cert.IPAddresses {
                ips[i] = ip.String()
            }

            showInfo("IP SANs", strings.Join(ips, " "))
        }

        if len(cert.EmailAddresses) > 0 {
            showInfo("Email SANs", strings.Join(cert.EmailAddresses, " "))
        }

        if len(cert.URIs) > 0 {
            uris := make([]string, len(cert.URIs))
            for i, uri := range cert.URIs {
                uris[i] = uri.String()
            }

            showInfo("URI SANs", strings.Join(uris, " "))
        }

        showInfo("Key Usage",     formatKeyUsage    (cert.KeyUsage))
        showInfo("Ext Key Usage", formatExtKeyUsage (cert.ExtKeyUsage))

        if showDetails {
            showInfo("Serial", cert.SerialNumber.String())
        }
        showInfo("SHA256", formatFingerprintSHA256(cert))

        if showDetails {

            showInfo("SHA1", formatFingerprintSHA1(cert))

            if len(cert.SubjectKeyId) > 0 {
                showInfo("SKI", formatHexWithColon(cert.SubjectKeyId))
            }

            if len(cert.AuthorityKeyId) > 0 {
                showInfo("AKI", formatHexWithColon(cert.AuthorityKeyId))
            }

            showInfo("NotBefore", cert.NotBefore.Format(time.RFC3339))
        }

        showInfo("NotAfter", cert.NotAfter.Format(time.RFC3339))

        fmt.Printf("\n")

        // Only show leaf cert
        if  false == showDetails {
            return
        }
    }
}


func formatFingerprintSHA256(cert *x509.Certificate) string {
    sum := sha256.Sum256(cert.Raw)
    return formatHexWithColon(sum[:])
}

func formatFingerprintSHA1(cert *x509.Certificate) string {
    sum := sha1.Sum(cert.Raw)
    return formatHexWithColon(sum[:])
}

func formatHexWithColon(data []byte) string {
    hexStr := hex.EncodeToString(data)
    var result string

    for i := 0; i < len(hexStr); i += 2 {
        if i > 0 {
            result += ":"
        }
        result += hexStr[i : i+2]
    }

    return result
}


func tlsCertsToX509(certs []tls.Certificate) ([]*x509.Certificate, error) {
    count := 0

    for _, c := range certs {
        count += len(c.Certificate)
    }

    chain := make([]*x509.Certificate, 0, count)

    for _, c := range certs {
        for _, der := range c.Certificate {
            cert, err := x509.ParseCertificate(der)
            if err != nil {
                return nil, err
            }

            chain = append(chain, cert)
        }
    }

    return chain, nil
}


func formatKeyUsage(usage x509.KeyUsage) string {

    var list []string

    if usage&x509.KeyUsageDigitalSignature != 0 {
        list = append(list, "DigitalSignature")
    }
    if usage&x509.KeyUsageContentCommitment != 0 {
        list = append(list, "ContentCommitment")
    }
    if usage&x509.KeyUsageKeyEncipherment != 0 {
        list = append(list, "KeyEncipherment")
    }
    if usage&x509.KeyUsageDataEncipherment != 0 {
        list = append(list, "DataEncipherment")
    }
    if usage&x509.KeyUsageKeyAgreement != 0 {
        list = append(list, "KeyAgreement")
    }
    if usage&x509.KeyUsageCertSign != 0 {
        list = append(list, "CertSign")
    }
    if usage&x509.KeyUsageCRLSign != 0 {
        list = append(list, "CRLSign")
    }
    if usage&x509.KeyUsageEncipherOnly != 0 {
        list = append(list, "EncipherOnly")
    }
    if usage&x509.KeyUsageDecipherOnly != 0 {
        list = append(list, "DecipherOnly")
    }

    if len(list) == 0 {
        return "None"
    }

    return strings.Join(list, ", ")
}


func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {

    var list []string

    for _, u := range usages {

        switch u {

        case x509.ExtKeyUsageServerAuth:
            list = append(list, "ServerAuth")

        case x509.ExtKeyUsageClientAuth:
            list = append(list, "ClientAuth")

        case x509.ExtKeyUsageCodeSigning:
            list = append(list, "CodeSigning")

        case x509.ExtKeyUsageEmailProtection:
            list = append(list, "EmailProtection")

        case x509.ExtKeyUsageTimeStamping:
            list = append(list, "TimeStamping")

        case x509.ExtKeyUsageOCSPSigning:
            list = append(list, "OCSPSigning")

        default:
            list = append(list, "Unknown")
        }
    }

    if len(list) == 0 {
        return "None"
    }

    return strings.Join(list, ", ")
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

func isClosedNetErr(err error) bool {
    if err == nil {
        return false
    }

    s := err.Error()
    // Common Go/net error when one goroutine closes the socket while another is blocked in Read
    return strings.Contains(s, "use of closed network connection")
}


func tlsResumeString(resumed bool) string {
    if resumed {
        return "resumed"
    }
    return "new"
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


func (cfg *SmtpProxyCfg) selectUpstreams() []string {
    switch cfg.RoutingMode {

    case RoutingModeLocalFirst:
        return append(cfg.LocalUpstreams, cfg.RemoteUpstreams...)

    case RoutingModeFailover:
        locals := cfg.loadBalanced(cfg.LocalUpstreams)
        return append(locals, cfg.RemoteUpstreams...)

    case RoutingModeLoadBalance:
        all := append(cfg.LocalUpstreams, cfg.RemoteUpstreams...)
        return cfg.loadBalanced(all)

    default:
        return cfg.LocalUpstreams
    }
}


func (cfg *SmtpProxyCfg) loadBalanced(list []string) []string {
    if len(list) <= 1 {
        return list
    }

    start := atomic.AddUint64(&cfg.counter, 1)
    result := make([]string, 0, len(list))

    for i := 0; i < len(list); i++ {
        index := int(start+uint64(i)) % len(list)
        result = append(result, list[index])
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


func watchCertificateFiles() {

    type fileState struct {
        path string
        mod  time.Time
    }

    files := []fileState{}

    if gCertFile != "" {
        files = append(files, fileState{path: gCertFile})
    }

    if gKeyFile != "" {
        files = append(files, fileState{path: gKeyFile})
    }

    if gCertFile2 != "" {
        files = append(files, fileState{path: gCertFile2})
    }

    if gKeyFile2 != "" {
        files = append(files, fileState{path: gKeyFile2})
    }

    // Initial timestamps
    for i := range files {
        if info, err := os.Stat(files[i].path); err == nil {
            files[i].mod = info.ModTime()
        }
    }

    for {
        changed := false

        for i := range files {

            info, err := os.Stat(files[i].path)
            if err != nil {
                continue
            }

            mod := info.ModTime()

            if mod.After(files[i].mod) {

                log.Printf("Certificate file changed: %s", files[i].path)

                files[i].mod = mod
                changed = true
            }
        }

        if changed {

            // allow tools writing cert+key to finish
            time.Sleep(1 * time.Second)

            if err := reloadCertificates(); err != nil {
                log.Printf("Certificate reload failed: %v", err)
            }
        }

        if sleepWithShutdownCheck (gCertUpdCheckSec) {
            break
        }
    }
}

