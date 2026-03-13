// smtproxy - SMTP Proxy in Go
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/signal"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

const (
    VersionMajor = 1
    VersionMinor = 0
    VersionPatch = 3

    VersionBuild int64 = VersionMajor*10000 + VersionMinor*100 + VersionPatch

    copyright = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    MICRO_CA_DIRECTORY         = "microca"
    MICRO_CA_CERT_FILE         = "microca.crt"
    MICRO_CA_KEY_FILE          = "microca.key"
    SERVER_CERT_FILE           = "server.crt"
    SERVER_KEY_FILE            = "server.key"

    ROUTING_MODE_FAILOVER      = "failover"
    ROUTING_MODE_LOADBALANCE   = "loadbalance"
    ROUTING_MODE_UNKNOWN       = "unknown"

    SMTPROXY_HEADER_PREFIX     = "X-SMTPROXY" // Must stay uppercase for compare
    SMTPROXY_HEADER_CLIENT     = "X-SMTProxy-Client"
    SMTPROXY_HEADER_TLS        = "X-SMTProxy-TLS"

    defaultListenAddr          = ":25"
    defaultTlsListenAddr       = ":465"
    defaultUpstream            = ":1025"
    defaultMetricsAddr         = ":9100"
    defaultTrustedProxies      = "127.0.0.1/32"
    defaultExcludeFromLogNets  = ""
    defaultDebugLogNets        = ""
    defaultRoutingMode         = ROUTING_MODE_FAILOVER
    defaultDNSServers          = ""
    defaultRequireTLS          = true
    defaultProxyProtoEnabled   = false
    defaultClientTLS13Only     = false
    defaultUpstreamTLS13Only   = false
    defaultUpstreamSTARTTLS    = true
    defaultUpstreamTLS         = false
    defaultUpstreamRequireTLS  = true
    defaultSkipCertValidation  = false
    defaultSendXCLIENT         = false
    defaultAddHeadersConnect   = false
    defaultAddHeadersTLS       = false
    defaultLogJSON             = false

    defaultCfgCheckIntervalSec = 120
    defaultClientTimeoutSec    = 120
    defaultCertDir             = "/tls"
    defaultMaxConnections      = 1000
    defaultMaxShutdownSeconds  = 60
    defaultCertUpdCheckSec     = 300
    defaultLogLevel            = LOG_ERROR
    defaultHandshakeLogLevel   = LOG_NONE
    defaultNoPTRFound          = "" // Empty string to indicate PTR is found

    env_smtproxy_ListenAddr          = "SMTPROXY_LISTEN_ADDR"
    env_smtproxy_TlsListenAddr       = "SMTPROXY_TLS_LISTEN_ADDR"
    env_smtproxy_RoutingMode         = "SMTPROXY_ROUTING_MODE"
    env_smtproxy_Upstream            = "SMTPROXY_UPSTREAM"
    env_smtproxy_TrustedProxies      = "SMTPROXY_TRUSTED_PROXIES"
    env_smtproxy_DebugLogNets        = "SMTPROXY_DEBUG_LOG_NETWORKS"
    env_smtproxy_ExcludeFromLogNets  = "SMTPROXY_EXCLUDE_FROM_LOG_NETWORKS"
    env_smtproxy_ProxyProto          = "SMTPROXY_PROXY_PROTO"
    env_smtproxy_DNSServers          = "SMTPROXY_DNS_SERVERS"
    env_smtproxy_RequireTLS          = "SMTPROXY_REQUIRE_TLS"
    env_smtproxy_TLS13Only           = "SMTPROXY_TLS13_ONLY"
    env_smtproxy_UpstreamTLS13Only   = "SMTPROXY_UPSTREAM_TLS13_ONLY"
    env_smtproxy_UpstreamSTARTTLS    = "SMTPROXY_UPSTREAM_STARTTLS"
    env_smtproxy_UpstreamTLS         = "SMTPROXY_UPSTREAM_TLS"
    env_smtproxy_UpstreamRequireTLS  = "SMTPROXY_UPSTREAM_REQUIRE_TLS"
    env_smtproxy_ServerName          = "SMTPROXY_SERVER_NAME"
    env_smtproxy_TrustedRootFile     = "SMTPROXY_TRUSTED_ROOT_FILE"
    env_smtproxy_SkipCertValidation  = "SMTPROXY_SKIP_CERT_VALIDATION"
    env_smtproxy_SendXCLIENT         = "SMTPROXY_SEND_XCLIENT"
    env_smtproxy_AddHeadersConnect   = "SMTPROXY_ADD_HEADERS_CONNECT"
    env_smtproxy_AddHeadersTLS       = "SMTPROXY_ADD_HEADERS_TLS"
    env_smtproxy_LogLevel            = "SMTPROXY_LOGLEVEL"
    env_smtproxy_LogJSON             = "SMTPROXY_LOGJSON"
    env_smtproxy_HandshakeLogLevel   = "SMTPROXY_HANDSHAKE_LOGLEVEL"
    env_smtproxy_ClientTimeoutSec    = "SMTPROXY_CLIENT_TIMEOUT"
    env_smtproxy_MaxConnections      = "SMTPROXY_MAX_CONNECTIONS"
    env_smtproxy_CertDir             = "SMTPROXY_CERT_DIR"
    env_smtproxy_MicroCaCurveName    = "SMTPROXY_MICROCA_CURVE_NAME"

    env_smtproxy_MaxShutdownSec      = "SMTPROXY_SHUTDOWN_SECONDS"
    env_smtproxy_CertUpdCheckSec     = "SMTPROXY_CERT_UPDATE_CHECK_SECONDS"
    env_smtproxy_MetricsListenAddr   = "SMTPROXY_METRICS_LISTEN_ADDR"
)

type LogLevel    int
type TLSMode     int
type RoutingMode int


type Stats struct
{
    SessionCounter         atomic.Int64
    SessionErrors          atomic.Int64
    ConnectionsActive      atomic.Int64
    ConnectionsTotal       atomic.Int64
    ConnectionsSuccess     atomic.Int64
    ConnectionsErrors      atomic.Int64
    TotalBytesWritten      atomic.Int64
    TotalBytesRead         atomic.Int64
    CertExpiration         atomic.Int64
    ConfigErrors           atomic.Int64
}

var stats Stats


// Global counters


var gBuildPlatform = "unknown"

// Global variables

var (

    gMicroCAName = "smtproxy-MicroCA"

    gLogLevel           LogLevel
    gLogHandshakeLevel  LogLevel

    gShutdownRequested  bool
    gLogJSON            bool
    gMaxShutdownSeconds int

    gMetricListnerAddr  string
    gServerName         string
    gCertDir            string
    gMicroCACurveName   string
    gCertUpdCheckSec    int

    gCertificates atomic.Value // Global CertStore

    gRdnsResolver      *RdnsResolver
    gDNSServers        []string
    gDNSServerCount    int

    gVersionStr     = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
    gGoVersion      = runtime.Version()
    gGoVersionBuild = parseGoVersionBuild(gGoVersion)
)

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
    RoutingModeFailover RoutingMode = iota
    RoutingModeLoadBalance
)


type SmtpProxyCfg struct {
    ListenAddr            string
    TLSListenAddr         string
    TrustStoreFile        string
    RoutingMode           RoutingMode
    ProxyProtoEnabled     bool
    TrustedProxies        []string
    ExcludeFromLogNets    []string
    DebugLogNets          []string
    Upstreams             []string
    ServerTLSConfig       *tls.Config
    IPNetExcludeFromLog   []*net.IPNet
    IPNetDebugLog         []*net.IPNet
    RequireTLS            bool
    ClientTLS13Only       bool
    UpstreamTLS13Only     bool
    UpstreamStartTLS      bool
    UpstreamImplicitTLS   bool
    UpstreamRequireTLS    bool
    SendXCLIENT           bool
    InsecureSkipVerify    bool
    AddHeadersConnect     bool
    AddHeadersTLS         bool
    TrustedRoots          *x509.CertPool
    UpstreamMinTLSVersion uint16
    ClientTimeout         time.Duration
    counter               int64
    MaxConnections        int64
}

type cacheEntry struct {
    host     string
    expire   time.Time
    negative bool
}

type RdnsResolver struct {
    resolver *net.Resolver

    cache      map[string]cacheEntry
    cacheMutex sync.RWMutex

    positiveTTL time.Duration
    negativeTTL time.Duration

    cacheHits    atomic.Int64
    cacheMisses  atomic.Int64
    dnsQueries   atomic.Int64
    dnsTimeouts  atomic.Int64
    dnsErrors    atomic.Int64
    dnsQueryTime atomic.Int64
}

func (m RoutingMode) String() string {

    switch m {

    case RoutingModeFailover:
        return ROUTING_MODE_FAILOVER

    case RoutingModeLoadBalance:
        return ROUTING_MODE_LOADBALANCE

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

    case ROUTING_MODE_FAILOVER:
        return RoutingModeFailover, nil

    case ROUTING_MODE_LOADBALANCE, "load-balance":
        return RoutingModeLoadBalance, nil
    }

    return RoutingModeFailover, fmt.Errorf("Invalid routing mode: %s", s)
}

type SmtpSession struct {
    cfg *SmtpProxyCfg

    sessionStart time.Time
    sessionID    int64

    client         net.Conn
    upstream       net.Conn
    clientReader   *bufio.Reader
    upstreamReader *bufio.Reader

    implicitTLS        bool
    inboundTLS         bool
    dataCmdReceived    bool
    dataHeadersDone    bool
    tunnelMode         bool
    clientTLSResumed   bool
    upstreamTLSResumed bool
    isError            bool

    clientTLSMode      TLSMode
    upstreamTLSMode    TLSMode
    clientNetIP        net.IP

    clientTLSVersion   string
    clientCipher       string
    clientCurveID      string
    clientIP           string
    clientHostName     string

    upstreamIP         string
    upstreamTarget     string
    upstreamTLSVersion string
    upstreamCipher     string
    upstreamCurveID    string

    sessionError  string
    responseLines []string
    countHelo     int

    bytesClientToUpstream int64
    bytesUpstreamToClient int64
}

var (
    smtpCommand_EHLO     = "EHLO %s\r\n"
    smtpCommand_STARTTLS = "STARTTLS\r\n"

    smtpResponse_GreetingBytes           = []byte("220 ESMTP Service ready\r\n")
    smtpResponse_StartTLSReadyBytes      = []byte("220 Ready to start TLS\r\n")
    smtpResponse_ServiceUnavailableBytes = []byte("421 Service not available\r\n")
    smtpResponse_TLSRequiredBytes        = []byte("530 Must issue STARTTLS first\r\n")
)

func showCfg(description, variableName, defaultValue, currentValue any) {
    logMsg("%-34s  %-34s %-30v  %v", variableName, description, defaultValue, currentValue)
}

func showInfo(description, currentValue any) {
    logMsg("%-15s:  %v", description, currentValue)
}

func showRuntimeInfo() {

    logSpace()
    logMsg("Runtime")
    logMsg("-------------------------")
    logSpace()

    info, err := readOSRelease()
    if err == nil {
        showInfo("Name", info["PRETTY_NAME"])
        showInfo("ID", info["ID"])
        showInfo("Version", info["VERSION_ID"])
    }

    showInfo("Go version", runtime.Version())
    showInfo("OS", runtime.GOOS)
    showInfo("Arch", runtime.GOARCH)
    showInfo("Platform", gBuildPlatform)

    showInfo("CPUs", runtime.NumCPU())
    showInfo("PID", os.Getpid())

    showInfo("UID/GID",   strconv.Itoa(os.Getuid())  + ":" + strconv.Itoa(os.Getgid()))
    showInfo("EUID/EGID", strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid()))
}

func shutdown() {

    logLine("Shutting down ...")
    gShutdownRequested = true

    // Wait one second to make sure the signal arrived at listeners before checking if active sessions must be drained
    time.Sleep(time.Second)

    logMsg("Waiting maximum %d seconds for shutdown ...", gMaxShutdownSeconds)

    for i := 0; i < gMaxShutdownSeconds; i++ {
        current := stats.ConnectionsActive.Load()

        if current == 0 {
            break
        }

        if i%10 == 0 {
            logMsg("Waiting for %d active connections ...", current)
        }

        time.Sleep(time.Second)
    }

    remaining := stats.ConnectionsActive.Load()

    if remaining > 0 {
        logMsg("Shutdown timeout after %d seconds, %d connections still active", gMaxShutdownSeconds, remaining)
    } else {
        logLine("All connections closed")
    }

    logLine("Shutdown completed")
}

func reloadCertificates() error {

    certs, err := loadCertificates()
    if err != nil {
        return err
    }

    gCertificates.Store(certs)

    time.Sleep(time.Second)

    logMsg("TLS certificates reloaded (%d certs)", len(certs))

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
            logMsg("SIGHUP received - Reloading certificates")
            reloadCertificates()

        case syscall.SIGINT, syscall.SIGTERM:
            logMsg("Shutdown signal received: %v", sig)
            shutdown()
            os.Exit(0)
        }
    }
}

func CreateMicroCAandCert() {

    count, _ := countFilesWithExtension(gCertDir, ".crt")
    if count > 0 {
        logMsg("%d certificate(s) in %s", count, gCertDir)
        return
    }

    microCADir := filepath.Join(gCertDir, MICRO_CA_DIRECTORY)

    logMsg("Creating MicroCA in %s", gCertDir)

    err := os.MkdirAll(microCADir, 0700)
    if err != nil {
        logMsg("ERROR: Failed to create MicroCA directory %s: %v", microCADir, err)
        return
    }

    CAKeyFile := filepath.Join(microCADir, MICRO_CA_KEY_FILE)
    CACertFile := filepath.Join(microCADir, MICRO_CA_CERT_FILE)

    KeyFile := filepath.Join(gCertDir, SERVER_KEY_FILE)
    CertFile := filepath.Join(gCertDir, SERVER_CERT_FILE)

    CreateCertAndKey(
        gServerName,
        gServerName,
        gMicroCAName,
        CAKeyFile,
        CACertFile,
        KeyFile,
        CertFile,
        gMicroCACurveName,
        true,
    )
}

func main() {

    log.SetFlags(0)

    var err error
    var printVersion  = flag.Bool("version", false, "print version")
    var showGoVersion = flag.Bool("goversion", false, "show the go runtime version")

    flag.Parse()

    if *printVersion {
        logMsg("%s", gVersionStr)
        return
    }

    // Get Log format first to ensure all logs are printed in the right format
    gLogJSON = getEnvBool (env_smtproxy_LogJSON, defaultLogJSON)

    logSpace()

    if *showGoVersion {
        showRuntimeInfo()
        return
    }

    go handleSignals()

    cfgUpstreams           := strings.Split(getEnv(env_smtproxy_Upstream,           defaultUpstream), ",")
    cfgTrustedProxies      := strings.Split(getEnv(env_smtproxy_TrustedProxies,     defaultTrustedProxies), ",")
    cfgExcludeFromLogNets  := strings.Split(getEnv(env_smtproxy_ExcludeFromLogNets, defaultExcludeFromLogNets), ",")
    cfgDebugLogNets        := strings.Split(getEnv(env_smtproxy_DebugLogNets,       defaultDebugLogNets), ",")
    cfgTrustStoreFile      := getEnv     (env_smtproxy_TrustedRootFile,             "")

    cfgListenAddr          := getEnv     (env_smtproxy_ListenAddr,               defaultListenAddr)
    cfgTLSListenAddr       := getEnv     (env_smtproxy_TlsListenAddr,            defaultTlsListenAddr)
    cfgProxyProtoEnabled   := getEnvBool (env_smtproxy_ProxyProto,               defaultProxyProtoEnabled)
    cfgRequireTLS          := getEnvBool (env_smtproxy_RequireTLS,               defaultRequireTLS)
    cfgUpstreamStartTLS    := getEnvBool (env_smtproxy_UpstreamSTARTTLS,         defaultUpstreamSTARTTLS)
    cfgUpstreamImplicitTLS := getEnvBool (env_smtproxy_UpstreamTLS,              defaultUpstreamTLS)
    cfgUpstreamRequireTLS  := getEnvBool (env_smtproxy_UpstreamRequireTLS,       defaultUpstreamRequireTLS)
    cfgClientTLS13Only     := getEnvBool (env_smtproxy_TLS13Only,                defaultClientTLS13Only)
    cfgUpstreamTLS13Only   := getEnvBool (env_smtproxy_UpstreamTLS13Only,        defaultUpstreamTLS13Only)
    cfgSkipCertValidation  := getEnvBool (env_smtproxy_SkipCertValidation,       defaultSkipCertValidation)
    cfgSendXCLIENT         := getEnvBool (env_smtproxy_SendXCLIENT,              defaultSendXCLIENT)
    cfgAddHeadersConnect   := getEnvBool (env_smtproxy_AddHeadersConnect,        defaultAddHeadersConnect)
    cfgAddHeadersTLS       := getEnvBool (env_smtproxy_AddHeadersTLS,            defaultAddHeadersTLS)
    cfgClientTimeoutSec    := getEnvInt  (env_smtproxy_ClientTimeoutSec,         defaultClientTimeoutSec)
    cfgMaxConnections      := getEnvInt64(env_smtproxy_MaxConnections,           defaultMaxConnections)

    gMaxShutdownSeconds    = getEnvInt   (env_smtproxy_MaxShutdownSec,           defaultMaxShutdownSeconds)
    gCertUpdCheckSec       = getEnvInt   (env_smtproxy_CertUpdCheckSec,          defaultCertUpdCheckSec)
    gMetricListnerAddr     = getEnv      (env_smtproxy_MetricsListenAddr,        defaultMetricsAddr)
    gLogLevel              = getEnvLogLevel(env_smtproxy_LogLevel,               defaultLogLevel)
    gLogHandshakeLevel     = getEnvLogLevel(env_smtproxy_HandshakeLogLevel,      defaultHandshakeLogLevel)
    gCertDir               = getEnv      (env_smtproxy_CertDir,                  defaultCertDir)
    gMicroCACurveName      = getEnv      (env_smtproxy_MicroCaCurveName, "")
    gDNSServers            = cleanList   (strings.Split(getEnv(env_smtproxy_DNSServers, defaultDNSServers), ","))
    gServerName            = getEnv(     env_smtproxy_ServerName, "")

    // Use host name if server name is not specified
    if gServerName == "" {
        gServerName, _ = os.Hostname()
    }

    if gServerName == "" {
        gServerName = "localhost"
    }

    cfgRoutingMode, ErrRoutingMode := ParseRoutingMode(getEnv(env_smtproxy_RoutingMode, defaultRoutingMode))

    if ErrRoutingMode != nil {
        logFatal("Invalid routing mode in configuration (%s) Valid options [%s|%s] : %v",
            env_smtproxy_RoutingMode, ROUTING_MODE_FAILOVER, ROUTING_MODE_LOADBALANCE, ErrRoutingMode)
    }

    CreateMicroCAandCert()

    certs, err := loadCertificates()

    // For now log errors but don't terminate

    if err != nil {
        stats.ConfigErrors.Add(1)
        logMsg("ERROR: Failed to load certificates: %v", err)
    }

    if len(certs) == 0 {
        stats.ConfigErrors.Add(1)
        logMsg("ERROR: No certificates found")
    }

    gCertificates.Store(certs)

    var upstreamMinTLSVersion uint16 = tls.VersionTLS12
    var clientMinTLSVersion   uint16 = tls.VersionTLS12

    // Set minimum TLS version

    if cfgClientTLS13Only {
        clientMinTLSVersion = tls.VersionTLS13
    }

    if cfgUpstreamTLS13Only {
        upstreamMinTLSVersion = tls.VersionTLS13
    }

    cfgServerTLS := &tls.Config{
        MinVersion:               clientMinTLSVersion,
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

                if supportsECDSA {
                    logMsg("%sClient supports ECDSA", prefix)
                } else {
                    logMsg("%sClient supports only RSA", prefix)
                }
            }

            for i := range certs {

                cert := &certs[i]
                err := chi.SupportsCertificate(cert)

                if err != nil {

                    if gLogHandshakeLevel >= LOG_INFO {
                        logMsg("%sCertificate %d rejected:", prefix, i)
                        logMsg("%s  Subject: %s", prefix, cert.Leaf.Subject)
                        logMsg("%s  Algorithm: %s", prefix, cert.Leaf.PublicKeyAlgorithm)
                        logMsg("%s  Reason: %v", prefix, err)
                    }

                    continue
                }

                if gLogHandshakeLevel >= LOG_INFO {
                    logMsg("%sCertificate %d selected:", prefix, i)
                    logMsg("%s  Subject: %s", prefix, cert.Leaf.Subject)
                    logMsg("%s  Algorithm: %s", prefix, cert.Leaf.PublicKeyAlgorithm)
                }

                return cert, nil
            }

            if gLogHandshakeLevel >= LOG_ERROR {
                logMsg("%sNo certificate matched, falling back to first", prefix)
            }

            return &certs[0], nil
        },
    }

    cfgLogExcludeNets, errLogExcludeNets := parseCIDRs(cleanList(cfgExcludeFromLogNets))
    cfgLogDebugNets,   errDebugLogNets   := parseCIDRs(cleanList(cfgDebugLogNets))

    cfg := &SmtpProxyCfg{
        ListenAddr:            cfgListenAddr,
        TLSListenAddr:         cfgTLSListenAddr,
        RoutingMode:           cfgRoutingMode,
        Upstreams:             cleanList(cfgUpstreams),
        TrustedProxies:        cleanList(cfgTrustedProxies),
        ExcludeFromLogNets:    cleanList(cfgExcludeFromLogNets),
        DebugLogNets:          cleanList(cfgDebugLogNets),
        IPNetExcludeFromLog:   cfgLogExcludeNets,
        IPNetDebugLog:         cfgLogDebugNets,
        ProxyProtoEnabled:     cfgProxyProtoEnabled,
        TrustStoreFile:        cfgTrustStoreFile,
        ServerTLSConfig:       cfgServerTLS,
        RequireTLS:            cfgRequireTLS,
        ClientTLS13Only:       cfgClientTLS13Only,
        UpstreamStartTLS:      cfgUpstreamStartTLS,
        UpstreamImplicitTLS:   cfgUpstreamImplicitTLS,
        UpstreamTLS13Only:     cfgUpstreamTLS13Only,
        UpstreamRequireTLS:    cfgUpstreamRequireTLS,
        InsecureSkipVerify:    cfgSkipCertValidation,
        UpstreamMinTLSVersion: upstreamMinTLSVersion,
        MaxConnections:        cfgMaxConnections,
        SendXCLIENT:           cfgSendXCLIENT,
        AddHeadersConnect:     cfgAddHeadersConnect,
        AddHeadersTLS:         cfgAddHeadersTLS,
        ClientTimeout:         time.Duration(cfgClientTimeoutSec) * time.Second,
    }

    if "" == cfg.TrustStoreFile {
        cfg.TrustedRoots, err = x509.SystemCertPool()

        if nil != err {
            logFatal("Failed to system trusted roots: %v", err)
        }

    } else {

        if !fileExists(cfg.TrustStoreFile) {
            stats.ConfigErrors.Add(1)
            logFatal("Trusted root file does not exist: %s (%s)", cfg.TrustStoreFile, env_smtproxy_TrustedRootFile)
        }

        cfg.TrustedRoots = x509.NewCertPool()
        ca, err := os.ReadFile(cfg.TrustStoreFile)

        if nil == err {
            cfg.TrustedRoots.AppendCertsFromPEM(ca)
        } else {
            logFatal("Failed to system trusted roots: %v", err)
        }
    }

    logSpace()
    logMsg("SMTP Proxy V%s", gVersionStr)
    logMsg("%s", dashLine(25))
    logSpace()

    logMsg("%s", copyright)
    logSpace()
    logSpace()

    showCfg("Description", "Variable", "Default", "Current")
    logMsg("%s", dashLine(140))

    logLevelValues    := fmt.Sprintf("%s|%s|%s|%s|%s", LOG_NONE, LOG_ERROR, LOG_INFO, LOG_VERBOSE, LOG_DEBUG)
    routingModeValues := fmt.Sprintf("%s|%s", RoutingModeFailover, RoutingModeLoadBalance)

    showCfg("Server name",                env_smtproxy_ServerName,          "<OS Hostname>",                      gServerName)
    showCfg("STARTTLS listen address",    env_smtproxy_ListenAddr,          formatStr(defaultListenAddr),         cfg.ListenAddr)
    showCfg("TLS      listen address",    env_smtproxy_TlsListenAddr,       formatStr(defaultTlsListenAddr),      cfg.TLSListenAddr)
    showCfg("Metrics  listen address",    env_smtproxy_MetricsListenAddr,   formatStr(defaultMetricsAddr),        gMetricListnerAddr)
    showCfg("List of upstream servers",   env_smtproxy_Upstream,            formatStr(defaultUpstream),           cfg.Upstreams)
    showCfg(routingModeValues,            env_smtproxy_RoutingMode,         defaultRoutingMode,                   cfg.RoutingMode)
    showCfg("DNS Servers",                env_smtproxy_DNSServers,          formatStr(defaultDNSServers),         gDNSServers)
    showCfg("Exclude from Log Networks",  env_smtproxy_ExcludeFromLogNets,  formatStr(defaultExcludeFromLogNets), cfg.ExcludeFromLogNets)
    showCfg("Debug Log Networks",         env_smtproxy_DebugLogNets,        formatStr(defaultDebugLogNets),       cfg.DebugLogNets)

    if gProxyProtocolSupported {
        showCfg("List of trusted proxies",    env_smtproxy_TrustedProxies,      formatStr(defaultTrustedProxies), cfg.TrustedProxies)
        showCfg("Use Proxy Protocol",         env_smtproxy_ProxyProto,          defaultProxyProtoEnabled,         cfg.ProxyProtoEnabled)
    }

    showCfg("Require TLS",                  env_smtproxy_RequireTLS,          defaultRequireTLS,                 cfg.RequireTLS)
    showCfg("Upstream use STARTTLS",        env_smtproxy_UpstreamSTARTTLS,    defaultUpstreamSTARTTLS,           cfg.UpstreamStartTLS)
    showCfg("Upstream requires TLS",        env_smtproxy_UpstreamRequireTLS,  defaultUpstreamRequireTLS,         cfg.UpstreamRequireTLS)
    showCfg("Upstream implicit TLS",        env_smtproxy_UpstreamTLS,         defaultUpstreamTLS,                cfg.UpstreamImplicitTLS)
    showCfg("TLS13 only",                   env_smtproxy_TLS13Only,           defaultClientTLS13Only,            cfg.ClientTLS13Only)
    showCfg("Upstream TLS13 only",          env_smtproxy_UpstreamTLS13Only,   defaultUpstreamTLS13Only,          cfg.UpstreamTLS13Only)
    showCfg("Skip cert validation",         env_smtproxy_SkipCertValidation,  defaultSkipCertValidation,         cfg.InsecureSkipVerify)
    showCfg("Use XCLIENT to signal client", env_smtproxy_SendXCLIENT,         defaultSendXCLIENT,                cfg.SendXCLIENT)
    // showCfg("Add Client IP/Host heeader",   env_smtproxy_AddHeadersConnect,   defaultAddHeadersConnect,          cfg.AddHeadersConnect)
    // showCfg("Add Client TLS info header",   env_smtproxy_AddHeadersTLS,       defaultAddHeadersTLS,              cfg.AddHeadersTLS)
    showCfg("Maximum sessions",             env_smtproxy_MaxConnections,      defaultMaxConnections,             cfg.MaxConnections)
    showCfg("Trusted root file",            env_smtproxy_TrustedRootFile,     "<System trust store>",            formatStr(cfg.TrustStoreFile))
    showCfg("Certificate directory",        env_smtproxy_CertDir,             formatStr(defaultCertDir),         formatStr(gCertDir))
    showCfg("Optional MicroCA CurveName",   env_smtproxy_MicroCaCurveName,    formatStr(""),                     gMicroCACurveName)
    showCfg("Client timeout (sec)",         env_smtproxy_ClientTimeoutSec,    defaultClientTimeoutSec,           cfg.ClientTimeout)
    showCfg("Max shutdown time (sec)",      env_smtproxy_MaxShutdownSec,      defaultMaxShutdownSeconds,         gMaxShutdownSeconds)
    showCfg("Cert Update Check (sec)",      env_smtproxy_CertUpdCheckSec,     defaultCertUpdCheckSec,            gCertUpdCheckSec)
    showCfg(logLevelValues,                 env_smtproxy_LogLevel,            defaultLogLevel,                   gLogLevel)
    showCfg("Handshake log level",          env_smtproxy_HandshakeLogLevel,   defaultHandshakeLogLevel,          gLogHandshakeLevel)
    showCfg("Log output is in JSON format", env_smtproxy_LogJSON,             defaultLogJSON,                    gLogJSON)

    if cfg.UpstreamImplicitTLS && cfg.UpstreamRequireTLS {
        logSpace()
        logMsg("Warning: Upstream STARTTLS and implicit TLS cannot be enabled at the same time!")
        logSpace()
    }

    showRuntimeInfo()
    logSpace()
    showInfo("Trust Store", len(cfg.TrustedRoots.Subjects()))

    gDNSServerCount = len(gDNSServers)

    if gDNSServerCount > 0 {
        gRdnsResolver = NewRdnsResolver(gDNSServers)
    }

    if gDNSServerCount > 0 {
        showInfo("Reverse DNS", gDNSServers)
    } else {
        showInfo("Reverse DNS", "disabled")
    }

    if gProxyProtocolSupported {
        showInfo("Proxy Protocol", "supported")
    }

    ConfigErrors :=  stats.ConfigErrors.Load()

    if ConfigErrors > 0 {
        logSpace()
        logMsg("WARNING - Configuration %d error(s) -- Please validate your configuration!", ConfigErrors)
        logSpace()
    }

    _ , err = parseCIDRs(cfg.TrustedProxies)
    if err != nil {
        logFatal("Invalid TrustedProxies CIDRs: %v", err)
    }

    if errLogExcludeNets != nil {
        logFatal("Invalid Log Exclude Networks CIDRs: %v", errLogExcludeNets)
    }

    if errDebugLogNets != nil {
        logFatal("Invalid Debug Log Networks CIDRs: %v", errDebugLogNets)
    }

    logSpace()

    if cfg.ProxyProtoEnabled {
        if !gProxyProtocolSupported {
            logFatal("Proxy Protocol configured but smtproxy is not compiled with Proxy Protocol support!")
        }
    }

    // Wait a second to let all the output flow before starting listeners
    time.Sleep(1 * time.Second)

    go watchCertificateFiles()

    logMsg("Starting listeners ...")
    logSpace()

    // Plain SMTP listener (STARTTLS capable)
    if cfg.ListenAddr != "" {
        go func() {
            listener, err := createListener(cfg.ListenAddr, cfg.ProxyProtoEnabled, cfg.TrustedProxies)
            if err != nil {
                logFatal("Cannot create listener: %v", err)
            }

            if cfg.ProxyProtoEnabled {
                logMsg("Listening with STARTTLS on [%s] (proxy protocol: enabled)", cfg.ListenAddr)
            } else {
                logMsg("Listening with STARTTLS on [%s]", cfg.ListenAddr)
            }

            for {
                conn, err := listener.Accept()

                if err != nil {
                    logMsg("Error accepting connection: %v", err)
                    continue
                }

                if errors.Is(err, net.ErrClosed) {
                    logMsg("STARTTLS listener closed")
                    break
                }

                if gShutdownRequested {
                    logMsg("STARTTLS listener shutdown")
                    conn.Close()
                    break
                }

                CurrentActiveConnections := stats.ConnectionsActive.Load()
                if CurrentActiveConnections >= int64(cfg.MaxConnections) {
                    logMsg("Connection limit reached (%d), rejecting [%s]", cfg.MaxConnections, conn.RemoteAddr())
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
            listener, err := createTlsListener(cfg.TLSListenAddr, cfg.ServerTLSConfig, cfg.ProxyProtoEnabled, cfg.TrustedProxies)

            if err != nil {
                logFatal("Cannot create TLS listener: %v", err)
            }

            if cfg.ProxyProtoEnabled {
                logMsg("Listening with SMTP TLS on [%s] (proxy protocol: enabled)", cfg.TLSListenAddr)
            } else {
                logMsg("Listening with SMTP TLS on [%s]", cfg.TLSListenAddr)
            }

            for {
                conn, err := listener.Accept()
                if err != nil {
                    logMsg("Error accepting connection: %v", err)
                    continue
                }

                if errors.Is(err, net.ErrClosed) {
                    logLine("TLS listener closed")
                    break
                }

                if gShutdownRequested {
                    logLine("TLS listener shutdown")
                    conn.Close()
                    break
                }

                CurrentActiveConnections := stats.ConnectionsActive.Load()
                if CurrentActiveConnections >= int64(cfg.MaxConnections) {
                    logMsg("Connection limit reached (%d), rejecting [%s]", cfg.MaxConnections, conn.RemoteAddr())
                    conn.Close()
                    continue
                }

                if gLogLevel >= LOG_DEBUG {
                    logMsg("Accepted new client from [%s] (Current Connections: %d)", conn.RemoteAddr(), CurrentActiveConnections)
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
    pattern := filepath.Join(gCertDir, "*.crt")

    crtFiles, err := filepath.Glob(pattern)
    if err != nil {
        return nil, fmt.Errorf("Failed to scan certificate directory %s: %v", gCertDir, err)
    }

    if len(crtFiles) == 0 {
        stats.ConfigErrors.Add(1)
        return nil, fmt.Errorf("No certificate files found in %s", gCertDir)
    }

    var certs []tls.Certificate
    var minExpiration int64

    for _, certFile := range crtFiles {

        keyFile := strings.TrimSuffix(certFile, ".crt") + ".key"

        if !fileExists(keyFile) {
            stats.ConfigErrors.Add(1)
            logMsg("Skipping certificate %s (missing key file %s)", certFile, keyFile)
            continue
        }

        cert, err := tls.LoadX509KeyPair(certFile, keyFile)
        if err != nil {
            stats.ConfigErrors.Add(1)
            return nil, fmt.Errorf("Failed to load certificate [%s] or key [%s]: %v", certFile, keyFile, err)
        }

        leaf, err := x509.ParseCertificate(cert.Certificate[0])
        if err != nil {
            return nil, fmt.Errorf("Failed to parse certificate %s: %v", certFile, err)
        }

        cert.Leaf = leaf
        certs = append(certs, cert)

        expiration := leaf.NotAfter.Unix()
        if minExpiration == 0 || expiration < minExpiration {
            minExpiration = expiration
        }

        dumpName := filepath.Base(certFile)

        if gLogLevel >= LOG_DEBUG {
            dumpCertificateChain(dumpName, []*x509.Certificate{leaf}, true)
        } else if gLogLevel >= LOG_VERBOSE {
            dumpCertificateChain(dumpName, []*x509.Certificate{leaf}, false)
        }
    }

    if len(certs) == 0 {
        return nil, fmt.Errorf("No usable certificate/key pairs found in %s", gCertDir)
    }

    stats.CertExpiration.Store (minExpiration)
    return certs, nil
}

func NewSmtpSession(client net.Conn, cfg *SmtpProxyCfg, implicitTLS bool) *SmtpSession {

    id := stats.SessionCounter.Add(1)

    stats.ConnectionsTotal.Add(1)

    return &SmtpSession{
        cfg:          cfg,
        client:       client,
        clientReader: bufio.NewReader(client),
        implicitTLS:  implicitTLS,

        sessionID:    id,
        sessionStart: time.Now(),
    }
}


func (s *SmtpSession) readClientLine() (string, error) {
    s.client.SetReadDeadline(time.Now().Add(60 * time.Second))

    line, err := s.clientReader.ReadString('\n')

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "C>  %q", line)
    }

    return line, err
}

func (s *SmtpSession) readUpstreamLine() (string, error) {
    s.upstream.SetReadDeadline(time.Now().Add(60 * time.Second))

    line, err := s.upstreamReader.ReadString('\n')

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "U>  %q", line)
    }

    return line, err
}

func (s *SmtpSession) writeClientBytes(dataBytes []byte) error {

    written, err := s.client.Write(dataBytes)
    s.bytesUpstreamToClient += int64(written)

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "C<  %q", string(dataBytes))
    }

    return err
}

func (s *SmtpSession) writeUpstreamStr(dataBytes string) error {
    written, err := s.upstream.Write([]byte(dataBytes))
    s.bytesClientToUpstream += int64(written)

    if gLogLevel >= LOG_DEBUG {
        s.logf(LOG_DEBUG, "U<  %q", dataBytes)
    }

    return err
}

func (s *SmtpSession) writeUpstreamHeader(headerName string, headerValue string) error {

    if headerName == "" {
        return nil
    }

    if headerValue == "" {
        return nil
    }

    line := fmt.Sprintf("%s: %s\r\n", headerName, headerValue)
    return s.writeUpstreamStr (line)
}

func (s *SmtpSession) connectUpstream() error {
    targets := s.cfg.selectUpstreams()

    s.logf(LOG_DEBUG, "Connect to Upstream: %v", targets)

    dialer := net.Dialer{
        Timeout: 5 * time.Second,
    }

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
                s.logNetError(err, "Upstream TLS connect [%s] failed: %v", target, err)
                continue
            }

            state := tlsConn.ConnectionState()
            s.upstreamTLSVersion = tlsVersionString(state.Version)
            s.upstreamCipher = tls.CipherSuiteName(state.CipherSuite)
            s.upstreamCurveID = state.CurveID.String()
            s.upstreamTLSMode = TLSModeImplicit
            s.upstreamTLSResumed = state.DidResume

            s.upstream = tlsConn
            s.upstreamReader = bufio.NewReader(tlsConn)

            _, err = s.readUpstreamLine()

            if err != nil {
                s.logNetError(err, "Cannot read from upstream connection [%s]: %v", target, err)
                tlsConn.Close()
                continue
            }

            s.upstreamTLSMode = TLSModeStartTLS
            s.logf(LOG_INFO, "Connected to upstream TLS [%s] (%s)", target, tlsInfoString(s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamCurveID, s.upstreamTLSResumed))

            return nil
        }

        // ----- Plain Connect -----

        conn, err := dialer.Dial("tcp", target)
        if err != nil {
            s.logNetError(err, "Cannot connect to upstream [%s] : %v", target, err)
            continue
        }

        reader := bufio.NewReader(conn)

        _, err = reader.ReadString('\n')
        if err != nil {
            s.logNetError(err, "Cannot read from upstream [%s] : %v", target, err)
            conn.Close()
            continue
        }

        fmt.Fprintf(conn, smtpCommand_EHLO, gServerName)

        supportsStartTLS := false

        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                s.logNetError(err, "Cannot read from upstream [%s] : %v", target, err)
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
                s.logNetError(err, "Cannot unexpected status returned from upstream [%s]. Response: [%v] : %v", target, resp, err)
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
                s.logNetError(err, "Handshake to upstream [%s] failed: %v", target, err)
                tlsConn.Close()
                goto nextTarget
            }

            state := tlsConn.ConnectionState()
            s.upstreamTLSVersion = tlsVersionString(state.Version)
            s.upstreamCipher = tls.CipherSuiteName(state.CipherSuite)
            s.upstreamCurveID = state.CurveID.String()
            s.upstreamTLSResumed = state.DidResume

            s.upstream = tlsConn
            s.upstreamReader = bufio.NewReader(tlsConn)
            s.upstreamTLSMode = TLSModeStartTLS

            s.logf(LOG_INFO, "Connected STARTTLS upstream [%s] (%s)", target, tlsInfoString(s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamCurveID, s.upstreamTLSResumed))

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
        s.logNetError(err, "Cannot write STARTTLS response to client: %v", err)
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

    s.inboundTLS = true
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
        if err := s.writeClientBytes([]byte(l));  err != nil {
            s.logNetError(err, "Cannot write response lines to client: %v", err)
        }
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

    clientTCP,   _ := s.client.(*net.TCPConn)
    upstreamTCP, _ := s.upstream.(*net.TCPConn)

    // Client -> Upstream
    go func() {
        n, err := io.Copy(s.upstream, s.client)

        if upstreamTCP != nil {
            _ = upstreamTCP.CloseWrite()
        }

        done <- tunnelResult{
            dir:   "client-upstream",
            bytes: n,
            err:   err,
        }
    }()

    // Upstream -> Client
    go func() {
        n, err := io.Copy(s.client, s.upstream)

        if clientTCP != nil {
            _ = clientTCP.CloseWrite()
        }

        done <- tunnelResult{
            dir:   "upstream-client",
            bytes: n,
            err:   err,
        }
    }()


    r1 := <-done

    if clientTCP != nil {
        _ = clientTCP.CloseRead()
    }

    if upstreamTCP != nil {
        _ = upstreamTCP.CloseRead()
    }

    _ = s.client.Close()
    _ = s.upstream.Close()

    r2 := <-done

    apply := func(r tunnelResult) {

        if r.dir == "client-upstream" {
            s.bytesClientToUpstream += r.bytes
        }

        if r.dir == "upstream-client" {
            s.bytesUpstreamToClient += r.bytes
        }

        if r.err != nil && !isClosedNetErr(r.err) {
            s.logNetError(r.err, "%s: %v", r.dir, r.err)
        }
    }

    apply(r1)
    apply(r2)
}

func (s *SmtpSession) sendXCLIENT() {

    if !s.cfg.SendXCLIENT {
        return
    }

    clientIP, _, _ := net.SplitHostPort(s.client.RemoteAddr().String())

    if clientIP == "" {
        clientIP = s.client.RemoteAddr().String()
    }

    cmd := fmt.Sprintf("XCLIENT ADDR=%s NAME=%s TLSVERSION=%s TLSCIPHER=%s TLSCURVE=%s\r\n", clientIP, s.clientHostName, s.clientTLSVersion, s.clientCipher, s.clientCurveID)

    s.logf(LOG_VERBOSE, "Sending XCLIENT: %s", strings.TrimSpace(cmd))

    if err := s.writeUpstreamStr(cmd); err != nil {
        s.logNetError(err, "XCLIENT failed: %v", err)
        return
    }

    resp, err := s.readUpstreamLine()

    if err != nil || !strings.HasPrefix(resp, "2") {
        s.logNetError(err, "Upstream rejected XCLIENT: %s", resp)
    }
}

func (s *SmtpSession) run() {

    var err error

    s.clientIP, _, err = net.SplitHostPort(s.client.RemoteAddr().String())
    if err != nil {
        s.clientIP = s.client.RemoteAddr().String()
    }

    s.clientNetIP = s.client.RemoteAddr().(*net.TCPAddr).IP

    var ok bool

    if gDNSServerCount > 0 {

        s.clientHostName, ok = gRdnsResolver.Lookup(s.clientIP)

        if !ok {
            s.clientHostName = defaultNoPTRFound
        }
    } else {
        s.clientHostName = ""
    }

    if err = s.connectUpstream(); err != nil {

        if err := s.writeClientBytes(smtpResponse_ServiceUnavailableBytes);  err != nil {
            s.logNetError(err, "Cannot write Service Unavailable to client: %v", err)
        }

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

            s.inboundTLS = true
            s.clientTLSMode = TLSModeImplicit // Client is already TLS connected

            s.logf(LOG_INFO, "Client implicit TLS [%s] (%s)", s.clientIP, tlsInfoString(s.clientTLSMode, s.clientTLSVersion, s.clientCipher, s.clientCurveID, s.clientTLSResumed))
        }
    }

    if err := s.writeClientBytes(smtpResponse_GreetingBytes); err != nil {
        s.logNetError(err, "Cannot write SMTP Greeting response to client: %v", err)
        return
    }

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
            s.logNetError(err, "Cannot read line from client: %v", err)
            return
        }

        // If data was received session is already in header mode
        if s.dataCmdReceived {

            header := strings.ToUpper(strings.TrimSpace(line))

            if strings.HasPrefix(header, SMTPROXY_HEADER_PREFIX) {
                s.logf(LOG_ERROR, "WARNING: Skipping spoofed header: %s", header)
                continue
            }

            // End of headers reached
            if header == "" {
                s.dataHeadersDone = true
                s.tunnelMode = true
                s.logf(LOG_DEBUG, "End of RFC822 headers detected -> Switching into tunnel mode")

                if s.cfg.AddHeadersConnect {
                    clientHeader := fmt.Sprintf("ip=%s host=%s", s.clientIP, s.clientHostName)
                    s.writeUpstreamHeader(SMTPROXY_HEADER_CLIENT, clientHeader)
                }

                if s.cfg.AddHeadersTLS {
                    if s.clientTLSVersion != "" {
                        tlsHeader := fmt.Sprintf("version=%s cipher=%s curve=%s", s.clientTLSVersion, s.clientCipher, s.clientCurveID)
                        s.writeUpstreamHeader(SMTPROXY_HEADER_TLS, tlsHeader)
                    }
                }
            }

            // Write received line
            if err := s.writeUpstreamStr(line); err != nil {
                s.logNetError(err, "Cannot write Upstream line: %v", err)
                return
            }

            continue
        }

        cmd := strings.ToUpper(strings.TrimSpace(line))

        if strings.HasPrefix(cmd, "EHLO ") ||
            strings.HasPrefix(cmd, "HELO ") {

            if err := s.handleEHLO(line); err != nil {
                s.logNetError(err, "Cannot handle EHLO/HELO command: %v", err)
                return
            }

            continue
        }

        if cmd == "STARTTLS" {

            if err := s.handleStartTLS(); err != nil {
                s.logNetError(err, "Cannot handle STARTTLS command: %v", err)
                return
            }

            // Send XCLIENT if configured after STARTTLS
            s.sendXCLIENT()
            s.tunnelMode = true
            s.logf(LOG_DEBUG, "STARTTLS Done -> Switching into tunnel mode")
            continue
        }

        // Check if in TLS only mode and return an error if channel is not secured
        if s.cfg.RequireTLS && !s.inboundTLS &&
            (strings.HasPrefix(cmd, "MAIL FROM") ||
             strings.HasPrefix(cmd, "RCPT TO") ||
             cmd == "DATA") {

            s.logf(LOG_INFO, "Connection requires TLS but is still unencrypted.")

            if err := s.writeClientBytes(smtpResponse_TLSRequiredBytes); err != nil {
                s.logf(LOG_ERROR, "Cannot write response to client: %v", err)
            }

            return
        }

        // Write received line
        if err := s.writeUpstreamStr(line); err != nil {
            s.logNetError(err, "Cannot write Upstream line: %v", err)
            return
        }

        // Read and forward response(including multi-line responses

        for {

            resp, err := s.readUpstreamLine()

            if err != nil {
                s.logNetError(err, "Cannot read Upstream response: %v", err)
                return
            }

            if err := s.writeClientBytes([]byte(resp)); err != nil {
                s.logNetError(err, "Cannot write response to client: %v", err)
                return
            }

            if s.dataCmdReceived || len(resp) < 4 || resp[3] != '-'{
                break
            }
        }

        if strings.HasPrefix(cmd, "DATA") {

            s.dataCmdReceived = true

            // Switch to tunnel mode when DATA received
            s.tunnelMode = true
            s.logf(LOG_DEBUG, "DATA command detected -> Switching into tunnel mode")
        }

    } // for
}

func handleConnection(client net.Conn, cfg *SmtpProxyCfg, implicitTLS bool) {

    stats.ConnectionsTotal.Add(1)
    stats.ConnectionsActive.Add(1)
    defer stats.ConnectionsActive.Add(-1)

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


func (cfg *SmtpProxyCfg) selectUpstreams() []string {
    switch cfg.RoutingMode {

    case RoutingModeLoadBalance:
        return cfg.loadBalanced(cfg.Upstreams)

    case RoutingModeFailover:
        fallthrough

    default:
        return cfg.Upstreams
    }
}

func (cfg *SmtpProxyCfg) loadBalanced(list []string) []string {
    if len(list) <= 1 {
        return list
    }

    start := atomic.AddInt64(&cfg.counter, 1)
    result := make([]string, len(list))

    for i := 0; i < len(list); i++ {
        result[i] = list[(int(start)+i)%len(list)]
    }

    return result
}

func watchCertificateFiles() {

    lastMod := time.Now()

    for {

        entries, err := os.ReadDir(gCertDir)
        if err != nil {
            logMsg("Failed to read certificate directory %s: %v", gCertDir, err)
        } else {

            var newest time.Time

            for _, e := range entries {

                if e.IsDir() {
                    continue
                }

                info, err := e.Info()
                if err != nil {
                    continue
                }

                mod := info.ModTime()

                if mod.After(newest) {
                    newest = mod
                }
            }

            if newest.After(lastMod) {

                logMsg("Certificate directory changed: %s", gCertDir)

                lastMod = newest

                // allow tools writing cert+key to finish
                time.Sleep(1 * time.Second)

                if err := reloadCertificates(); err != nil {
                    logMsg("Certificate reload failed: %v", err)
                }
            }
        }

        if sleepWithShutdownCheck(gCertUpdCheckSec) {
            break
        }
    }
}

func readOSRelease() (map[string]string, error) {

    file, err := os.Open("/etc/os-release")
    if err != nil {
        return nil, err
    }
    defer file.Close()

    data := make(map[string]string)
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        line := scanner.Text()

        if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
            continue
        }

        parts := strings.SplitN(line, "=", 2)
        key := parts[0]
        val := strings.Trim(parts[1], `"`)

        data[key] = val
    }

    return data, scanner.Err()
}

func NewRdnsResolver(dnsServers []string) *RdnsResolver {

    dialer := &net.Dialer{
        Timeout: 3 * time.Second,
    }

    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {

            server := dnsServers[time.Now().UnixNano()%int64(len(dnsServers))]
            return dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
        },
    }

    return &RdnsResolver{
        resolver:    resolver,
        cache:       make(map[string]cacheEntry),
        positiveTTL: 30 * time.Minute,
        negativeTTL: 10 * time.Minute,
    }
}

func (r *RdnsResolver) cacheLookup(ip string) (string, bool, bool) {

    now := time.Now()

    r.cacheMutex.RLock()
    entry, ok := r.cache[ip]
    r.cacheMutex.RUnlock()

    if !ok || now.After(entry.expire) {
        return "", false, false
    }

    r.cacheHits.Add(1)

    if entry.negative {
        return "", true, true
    }

    return entry.host, true, false
}

func (r *RdnsResolver) cacheStore(ip string, host string, negative bool) {

    expire := r.positiveTTL
    if negative {
        expire = r.negativeTTL
    }

    entry := cacheEntry{
        host:     host,
        expire:   time.Now().Add(expire),
        negative: negative,
    }

    r.cacheMutex.Lock()
    r.cache[ip] = entry
    r.cacheMutex.Unlock()
}

func (r *RdnsResolver) Lookup(ip string) (string, bool) {

    if host, ok, negative := r.cacheLookup(ip); ok {

        if negative {
            return "", false
        }

        return host, true
    }

    r.cacheMisses.Add(1)
    r.dnsQueries.Add(1)

    start := time.Now()

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    names, err := r.resolver.LookupAddr(ctx, ip)

    duration := time.Since(start)
    r.dnsQueryTime.Add(duration.Nanoseconds())

    if err != nil {

        if errors.Is(err, context.DeadlineExceeded) {
            r.dnsTimeouts.Add(1)
        } else {
            r.dnsErrors.Add(1)
        }

        r.cacheStore(ip, "", true)
        return "", false
    }

    if len(names) == 0 {

        r.dnsErrors.Add(1)

        r.cacheStore(ip, "", true)
        return "", false
    }

    host := strings.TrimSuffix(names[0], ".")

    r.cacheStore(ip, host, false)

    return host, true
}
