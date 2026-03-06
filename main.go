package main

import (
    "bufio"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/hex"
    "io"
    "log"
    "net"
    "os"
    "strings"
    "sync/atomic"
    "flag"
    "fmt"
    "time"
    "strconv"
)


type LogLevel int
type TLSMode  int
type RoutingMode int

var gSessionCounter   uint64
var gSessionError     uint64
var gActiveConnections int64

var gLogLevel           LogLevel
var gLogHandshakeLevel  LogLevel

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
    RoutingMode           RoutingMode

    CertFile              string
    KeyFile               string
    CertFile2             string
    KeyFile2              string
    TrustStoreFile        string

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
        return "ImplicitTLS"

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
    clientIP           string
    upstreamIP         string
    upstreamTarget     string
    upstreamTLSVersion string
    upstreamCipher     string

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
    version   = "0.9.3"
    copyright = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    defaultListenAddr          = ":1025"
    defaultTlsListenAddr       = ":1465"
    defaultLocalUpstream       = ":25"
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
    defaultMaxConnections      = 100

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
    env_smtproxy_client_timeout     = "SMTPROXY_CLIENT_TIMEOUT"
    env_smtproxy_max_connections    = "SMTPROXY_MAX_CONNECTIONS"

    env_smtproxy_cert_file          = "SMTPROXY_CERT_FILE"
    env_smtproxy_key_file           = "SMTPROXY_KEY_FILE"
    env_smtproxy_cert_file2         = "SMTPROXY_CERT_FILE2"
    env_smtproxy_key_file2          = "SMTPROXY_KEY_FILE2"
)


func showHelpEnv() {

    fmt.Printf("\n");

    fmt.Printf("Environment variables\n");
    fmt.Printf("---------------------\n");
    fmt.Printf("\n");
    fmt.Printf("%-35s   STARTTLS listen address (default: %s)\n", env_smtproxy_ListenAddr,    formatStr(defaultListenAddr));
    fmt.Printf("%-35s   TLS      listen address (default: %s)\n", env_smtproxy_TlsListenAddr, formatStr(defaultTlsListenAddr));
    fmt.Printf("%-35s   Routing Mode [%s|%s|%s] (default: %s)\n", env_smtproxy_RoutingMode,   RoutingModeLocalFirst, RoutingModeFailover, RoutingModeLoadBalance, RoutingModeLocalFirst);

    fmt.Printf("%-35s   Local  Upstreams (default: %s)\n",      env_smtproxy_LocalUpstreams,     formatStr(defaultLocalUpstream));
    fmt.Printf("%-35s   Remote Upstreams (default: %s)\n",      env_smtproxy_RemoteUpstreams,    formatStr(defaultRemoteUpstream));
    fmt.Printf("%-35s   Require TLS           (default: %v)\n", env_smtproxy_RequireTLS,         defaultRequireTLS);
    fmt.Printf("%-35s   Upstream use STARTTLS (default: %v)\n", env_smtproxy_UpstreamSTARTTLS,   defaultUpstreamSTARTTLS);
    fmt.Printf("%-35s   Upstream requires TLS (default: %v)\n", env_smtproxy_UpstreamRequireTLS, defaultUpstreamRequireTLS);
    fmt.Printf("%-35s   Upstream implicit TLS (default: %v)\n", env_smtproxy_UpstreamTLS,        defaultUpstreamTLS);
    fmt.Printf("%-35s   TLS13 Only            (default: %v)\n", env_smtproxy_TLS13Only,          defaultClientTLS13Only);
    fmt.Printf("%-35s   Upstream TLS13 Only   (default: %v)\n", env_smtproxy_UpstreamTLS13Only,  defaultUpstreamTLS13Only);
    fmt.Printf("%-35s   Skip cert validation  (default: %v)\n", env_smtproxy_SkipCertValidation, defaultSkipCertValidation);
    fmt.Printf("%-35s   XCLIENT to signal IP  (default: %v)\n", env_smtproxy_SendXCLIENT,        defaultSendXCLIENT);
    fmt.Printf("%-35s   Maximum sessions      (default: %d)\n", env_smtproxy_max_connections,    defaultMaxConnections);
    fmt.Printf("%-35s   Trusted Root File     (default: %s)\n", env_smtproxy_TrustedRootFile,    "<System trust store>");

    fmt.Printf("%-35s   Certificate File      (default: %v)\n", env_smtproxy_cert_file,          formatStr(defaultCertFile));
    fmt.Printf("%-35s   Private Key File      (default: %v)\n", env_smtproxy_key_file,           formatStr(defaultKeyFile));
    fmt.Printf("%-35s   Certificate File2     (default: %v)\n", env_smtproxy_cert_file2,         formatStr(defaultCertFile2));
    fmt.Printf("%-35s   Private Key File2     (default: %v)\n", env_smtproxy_key_file2,          formatStr(defaultKeyFile2));

    fmt.Printf("%-35s   Server name\n",                         env_smtproxy_ServerName);
    fmt.Printf("%-35s   Log level\n",                           env_smtproxy_LogLevel);
    fmt.Printf("%-35s   Handshake Log level\n",                 env_smtproxy_HandshakeLogLevel);
    fmt.Printf("\n");
}


func main() {

    var showVersion = flag.Bool("version", false, "show version")
    var showEnv     = flag.Bool("env", false, "show environment variable help")

    flag.Parse()

    if *showVersion {
        fmt.Printf("%s", version)
        return
    }

    if *showEnv {
        showHelpEnv()
        return
    }

    fmt.Printf("\n")

    listenAddr          := getEnv(env_smtproxy_ListenAddr,    defaultListenAddr)
    tlsListenAddr       := getEnv(env_smtproxy_TlsListenAddr, defaultTlsListenAddr)
    trustStoreFile      := strings.ToLower(getEnv(env_smtproxy_TrustedRootFile, ""))

    localUpstreams      := strings.Split (getEnv(env_smtproxy_LocalUpstreams,  defaultLocalUpstream), ",")
    remoteUpstreams     := strings.Split (getEnv(env_smtproxy_RemoteUpstreams, defaultRemoteUpstream), ",")

    requireTLS          := GetEnvBool(env_smtproxy_RequireTLS,         defaultRequireTLS)
    upstreamStartTLS    := GetEnvBool(env_smtproxy_UpstreamSTARTTLS,   defaultUpstreamSTARTTLS)
    upstreamImplicitTLS := GetEnvBool(env_smtproxy_UpstreamTLS,        defaultUpstreamTLS)
    upstreamRequireTLS  := GetEnvBool(env_smtproxy_UpstreamRequireTLS, defaultUpstreamRequireTLS)
    clientTLS13Only     := GetEnvBool(env_smtproxy_TLS13Only,          defaultClientTLS13Only)
    upstreamTLS13Only   := GetEnvBool(env_smtproxy_UpstreamTLS13Only,  defaultUpstreamTLS13Only)
    skipCertValidation  := GetEnvBool(env_smtproxy_SkipCertValidation, defaultSkipCertValidation)
    sendXCLIENT         := GetEnvBool(env_smtproxy_SendXCLIENT,        defaultSendXCLIENT)
    clientTimeoutSec    := getEnvInt(env_smtproxy_client_timeout,      defaultClientTimeoutSec)
    maxConnections      := getEnvInt64(env_smtproxy_max_connections,   defaultMaxConnections)

    gLogLevel          = LogLevel(getEnvInt(env_smtproxy_LogLevel, 0))
    gLogHandshakeLevel = LogLevel(getEnvInt(env_smtproxy_HandshakeLogLevel, 0))

    certFile  := getEnv(env_smtproxy_cert_file,  defaultCertFile)
    keyFile   := getEnv(env_smtproxy_key_file,   defaultKeyFile)
    certFile2 := getEnv(env_smtproxy_cert_file2, defaultCertFile2)
    keyFile2  := getEnv(env_smtproxy_key_file2,  defaultKeyFile2)

    routingMode, ErrRoutingMode := ParseRoutingMode(getEnv(env_smtproxy_RoutingMode, ""))

    if ErrRoutingMode != nil {
        log.Fatalf("Invalid routing mode in configuration (%s) Valid options [%s|%s|%s] : %v",
            env_smtproxy_RoutingMode, RoutingModeLocalFirst, RoutingModeFailover, RoutingModeLoadBalance, ErrRoutingMode)
    }

    if !fileExists (certFile) {
        log.Fatalf("Certificate file does not exist: %s (%s)", certFile, env_smtproxy_cert_file)
    }

    if !fileExists (keyFile) {
        log.Fatalf("Key file does not exist: %s (%s)", keyFile, env_smtproxy_key_file)
    }

    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("Failed to load certificate (%s/%s): %v", env_smtproxy_cert_file, env_smtproxy_key_file, err)
    }

    certs := []tls.Certificate{cert}

    if certFile2 != "" && keyFile2 != "" {

        if !fileExists (certFile2) {
            log.Fatalf("Certificate file does not exist: %s (%s)", certFile2, env_smtproxy_cert_file2)
        }

        if !fileExists (keyFile2) {
            log.Fatalf("Key file does not exist: %s (%s)", keyFile2, env_smtproxy_key_file2)
        }

        cert2, err := tls.LoadX509KeyPair(certFile2, keyFile2)
        if err != nil {
            log.Fatalf("Failed to load second certificate (%s/%s): %v", env_smtproxy_cert_file2, env_smtproxy_key_file2, err)
        }

        certs = append(certs, cert2)

        log.Printf("Additional certificate loaded")
    }

    // Make sure the certificate is parsed already
    for i := range certs {
        leaf, err := x509.ParseCertificate(certs[i].Certificate[0])
        if err != nil {
            log.Fatal("Failed to parse certificate:", err)
        }

        certs[i].Leaf = leaf
    }

    x509Certs, err := tlsCertsToX509(certs)
    if err != nil {
        log.Fatal("Failed to parse certificates:", err)
    }

    dumpCertificateChain("Server Certificates", x509Certs)

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

        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },

        GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {

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

        CertFile:              certFile,
        KeyFile:               keyFile,
        CertFile2:             certFile2,
        KeyFile2:              keyFile2,
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

    fmt.Printf("\n--- SMTP Proxy Configuration ---\n\n")

    fmt.Printf("V%s %s\n\n", version, copyright)

    fmt.Printf("STARTTLS Listener       :  %s\n", cfg.ListenAddr)
    fmt.Printf("TLS Listener            :  %s\n", cfg.TLSListenAddr)
    fmt.Printf("Local Upstreams         :  %v\n", cfg.LocalUpstreams)
    fmt.Printf("Remote Upstreams        :  %v\n", cfg.RemoteUpstreams)
    fmt.Printf("Routing Mode            :  %s\n", cfg.RoutingMode)
    fmt.Printf("Require TLS             :  %v\n", cfg.RequireTLS)
    fmt.Printf("Upstream require TLS    :  %v\n", cfg.UpstreamRequireTLS)
    fmt.Printf("Skip cert validation    :  %v\n", cfg.InsecureSkipVerify)
    fmt.Printf("TLS13 Only              :  %v\n", cfg.ClientTLS13Only)
    fmt.Printf("Upstream TLS 1.3 Only   :  %v\n", cfg.UpstreamTLS13Only)
    fmt.Printf("Upstream implicit TLS   :  %v\n", cfg.UpstreamImplicitTLS)
    fmt.Printf("Send XCLIENT info       :  %v\n", cfg.SendXCLIENT)
    fmt.Printf("Client timeout          :  %v\n", cfg.ClientTimeout)
    fmt.Printf("Max connections         :  %v\n", cfg.MaxConnections)
    fmt.Printf("Log Level               :  %s (%d)\n", gLogLevel, gLogLevel)
    fmt.Printf("Handshake Log Level     :  %s (%d)\n", gLogHandshakeLevel, gLogHandshakeLevel)
    fmt.Printf("Trusted Roots           :  %d\n", len(cfg.TrustedRoots.Subjects()))
    fmt.Printf("Trust store file        :  %s\n", cfg.TrustStoreFile)
    fmt.Printf("Certificate file        :  %s\n", cfg.CertFile)
    fmt.Printf("Private key file        :  %s\n", cfg.KeyFile)
    fmt.Printf("2nd Certificate file    :  %s\n", cfg.CertFile2)
    fmt.Printf("2nd Private key file    :  %s\n", cfg.KeyFile2)
    fmt.Printf("Trusted Roots File      :  %s\n", cfg.TrustStoreFile)

    fmt.Printf("\n")

    if  cfg.UpstreamImplicitTLS && cfg.UpstreamRequireTLS {
        fmt.Printf("Warning: Upstream STARTTLS and implicit TLS cannot be enabled at the same time!\n\n")
    }

    // Plain SMTP listener (STARTTLS capable)
    if cfg.ListenAddr != "" {
        go func() {
            listener, err := net.Listen("tcp", cfg.ListenAddr)
            if err != nil {
                log.Fatal(err)
            }

            log.Printf("Listening with STARTTLS on %s", cfg.ListenAddr)

            for {
                conn, err := listener.Accept()
                if err != nil {
                    log.Println(err)
                    continue
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

    select {}
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
            s.logf(LOG_INFO, "Connected to upstream TLS [%s] (%s)", target, tlsInfoString (s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamTLSResumed))

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
            s.upstreamTLSResumed = state.DidResume

            s.upstream = tlsConn
            s.upstreamReader = bufio.NewReader(tlsConn)
            s.upstreamTLSMode = TLSModeStartTLS

            s.logf(LOG_INFO, "Connected STARTTLS upstream [%s] (%s)", target, tlsInfoString (s.upstreamTLSMode, s.upstreamTLSVersion, s.upstreamCipher, s.upstreamTLSResumed))

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
    s.clientCipher = tls.CipherSuiteName(state.CipherSuite)
    s.clientTLSResumed = state.DidResume

    s.client = tlsConn
    s.clientReader = bufio.NewReader(tlsConn)

    s.inboundTLS = true
    s.clientTLSMode = TLSModeStartTLS

    s.logf(LOG_INFO, "Client STARTTLS established [%s] (%s)", s.clientIP, tlsInfoString(s.clientTLSMode, s.clientTLSVersion, s.clientCipher, s.clientTLSResumed))

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

    cmd := fmt.Sprintf("XCLIENT ADDR=%s TLSVERSION=%s TLSCIPHER=%s\r\n", clientIP, s.clientTLSVersion, s.clientCipher)

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
            s.clientCipher = tls.CipherSuiteName(state.CipherSuite)
            s.clientTLSResumed = state.DidResume

            s.inboundTLS = true
            s.clientTLSMode = TLSModeImplicit // Client is already TLS connected

            s.logf(LOG_INFO, "Client implicit TLS [%s] (%s)", s.clientIP, tlsInfoString(s.clientTLSMode, s.clientTLSVersion, s.clientCipher, s.clientTLSResumed))
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

    defer client.Close()
    session := NewSmtpSession(client, cfg, implicitTLS)
    session.run()
    session.logSessionSummary()
}


func tlsInfoString(mode TLSMode, version, cipher string, resumed bool) string {

    if mode == TLSModeNone {
        return mode.String()
    }

    resume := "new"

    if resumed {
        resume = "resumed"
    }

    return fmt.Sprintf("%s %s %s %s", mode, version, cipher, resume)
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
            s.clientTLSResumed,
        ),
        s.upstreamTarget,
        tlsInfoString(
            s.upstreamTLSMode,
            s.upstreamTLSVersion,
            s.upstreamCipher,
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


func GetEnvBool(name string, def bool) bool {
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


func dumpCertificateChain(description string, chain []*x509.Certificate) {

    fmt.Printf("\n")
    fmt.Printf("---------------------------------------------------\n")
    fmt.Printf("Certificates(%d) %s\n", len(chain), description)
    fmt.Printf("---------------------------------------------------\n")
    fmt.Printf("\n")

    for i, cert := range chain {
        fmt.Printf("----- Certificate %d -----\n\n", i)

        if i == 0 {
            fmt.Printf("%-15s : %s\n", "Type", "Leaf")
        } else {
            fmt.Printf("%-15s : %s\n", "Type", "Intermediate/CA")
        }

        fmt.Printf("%-15s : %s\n", "Subject", cert.Subject.String())
        fmt.Printf("%-15s : %s\n", "Issuer", cert.Issuer.String())

        if len(cert.DNSNames) > 0 {
            fmt.Printf("%-15s : %s\n", "DNS SANs", strings.Join(cert.DNSNames, " "))
        }

        if len(cert.IPAddresses) > 0 {
            ips := make([]string, len(cert.IPAddresses))
            for i, ip := range cert.IPAddresses {
                ips[i] = ip.String()
            }

            fmt.Printf("%-15s : %s\n", "IP SANs", strings.Join(ips, " "))
        }

        if len(cert.EmailAddresses) > 0 {
            fmt.Printf("%-15s : %s\n", "Email SANs", strings.Join(cert.EmailAddresses, " "))
        }

        if len(cert.URIs) > 0 {
            uris := make([]string, len(cert.URIs))
            for i, uri := range cert.URIs {
                uris[i] = uri.String()
            }

            fmt.Printf("%-15s : %s\n", "URI SANs", strings.Join(uris, " "))
        }

        fmt.Printf("%-15s : %s\n", "Serial", cert.SerialNumber.String())
        fmt.Printf("%-15s : %s\n", "SHA256", formatFingerprintSHA256(cert))
        fmt.Printf("%-15s : %s\n", "SHA1", formatFingerprintSHA1(cert))

        if len(cert.SubjectKeyId) > 0 {
            fmt.Printf("%-15s : %s\n", "SKI", formatHexWithColon(cert.SubjectKeyId))
        }

        if len(cert.AuthorityKeyId) > 0 {
            fmt.Printf("%-15s : %s\n", "AKI", formatHexWithColon(cert.AuthorityKeyId))
        }

        fmt.Printf("%-15s : %s\n", "NotBefore", cert.NotBefore.Format(time.RFC3339))
        fmt.Printf("%-15s : %s\n", "NotAfter", cert.NotAfter.Format(time.RFC3339))

        fmt.Printf("\n")
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
    log.Printf("%sClient: %s, SNI: %s", prefix, chi.ServerName)

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
