

SMTP Proxy V0.9.3
-------------------------

Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved.


Variable                            Description                        Default                         Current
--------------------------------------------------------------------------------------------------------------------------------------------
SMTPROXY_LISTEN_ADDR                STARTTLS listen address            :1025                           :1025
SMTPROXY_TLS_LISTEN_ADDR            TLS      listen address            :1465                           :1465
SMTPROXY_METRICS_ADDR               Metrics  listen address            :9101                           :9101
SMTPROXY_ROUTING_MODE               Routing mode                       local-first                     local-first
SMTPROXY_LOCAL_UPSTREAMS            Local  upstreams                   :25                             [:25]
SMTPROXY_REMOTE_UPSTREAMS           Remote upstreams                   []                              []
SMTPROXY_REQUIRE_TLS                Require TLS                        true                            true
SMTPROXY_UPSTREAM_STARTTLS          Upstream use STARTTLS              true                            true
SMTPROXY_UPSTREAM_REQUIRE_TLS       Upstream requires TLS              true                            true
SMTPROXY_UPSTREAM_TLS               Upstream implicit TLS              false                           false
SMTPROXY_TLS13_ONLY                 TLS13 only                         false                           false
SMTPROXY_UPSTREAM_TLS13_ONLY        Upstream TLS13 only                false                           false
SMTPROXY_SKIP_CERT_VALIDATION       Skip cert validation               false                           false
SMTPROXY_SEND_XCLIENT               XCLIENT to signal IP               false                           false
SMTPROXY_MAX_CONNECTIONS            Maximum sessions                   1000                            1000
SMTPROXY_TRUSTED_ROOT_FILE          Trusted root file                  <System trust stor>             []
SMTPROXY_CERT_FILE                  Certificate file                   /tls/tls.crt                    /tls/tls.crt
SMTPROXY_KEY_FILE                   Private key file                   /tls/tls.key                    /tls/tls.key
SMTPROXY_CERT_FILE2                 Certificate file2                  []                              []
SMTPROXY_KEY_FILE2                  Private key file2                  []                              []
SMTPROXY_CLIENT_TIMEOUT             Client timeout (sec)               120                             2m0s
SMTPROXY_SHUTDOWN_SECONDS           Max shutdown time (sec)            60                              60
SMTPROXY_LOGLEVEL                   Log level                          ERROR                           ERROR
SMTPROXY_HANDSHAKE_LOGLEVEL         Handshake Log level                NONE                            NONE

Routing mode values:
  [local-first|failover|loadbalance]

Log level values:
  0=NONE 1=ERROR 2=INFO 3=VERBOSE 4=DEBUG


Runtime
-------------------------

Go version     :  go1.26.1
OS             :  linux
Arch           :  amd64
CPUs           :  8
PID            :  1038119
Trust Store    :  148

2026/03/06 19:39:12 Starting listeners ...

2026/03/06 19:39:12 Listening at /metrics   on [:9101]
2026/03/06 19:39:12 Listening with SMTP TLS on [:1465]
2026/03/06 19:39:12 Listening with STARTTLS on [:1025]
2026/03/06 19:39:23 Shutting down ...
2026/03/06 19:39:24 Waiting maximum 60 seconds for shutdown ...
2026/03/06 19:39:24 All connections closed
