
```
Environment variables
---------------------

SMTPROXY_LISTEN_ADDR                  STARTTLS listen address (default: :1025)
SMTPROXY_TLS_LISTEN_ADDR              TLS      listen address (default: :1465)
SMTPROXY_ROUTING_MODE                 Routing Mode [local-first|failover|loadbalance] (default: local-first)
SMTPROXY_LOCAL_UPSTREAMS              Local  Upstreams (default: :25)
SMTPROXY_REMOTE_UPSTREAMS             Remote Upstreams (default: [])
SMTPROXY_REQUIRE_TLS                  Require TLS           (default: true)
SMTPROXY_UPSTREAM_STARTTLS            Upstream use STARTTLS (default: true)
SMTPROXY_UPSTREAM_REQUIRE_TLS         Upstream require TLS  (default: true)
SMTPROXY_UPSTREAM_TLS                 Upstream implicit TLS (default: false)
SMTPROXY_TLS13_ONLY                   TLS13 Only            (default: false)
SMTPROXY_UPSTREAM_TLS13_ONLY          Upstream TLS13 Only   (default: false)
SMTPROXY_SKIP_CERT_VALIDATION         Skip cert validation  (default: false)
SMTPROXY_SEND_XCLIENT                 XCLIENT to signal IP  (default: false)
SMTPROXY_MAX_CONNECTIONS              Maximum sessions      (default: 100)
SMTPROXY_TRUSTED_ROOT_FILE            Trusted Root File     (default: <System trust store>)
SMTPROXY_CERT_FILE                    Certificate File      (default: /tls/tls.crt)
SMTPROXY_KEY_FILE                     Private Key File      (default: /tls/tls.key)
SMTPROXY_CERT_FILE2                   Certificate File2     (default: [])
SMTPROXY_KEY_FILE2                    Private Key File2     (default: [])
SMTPROXY_SERVER_NAME                  Server name
SMTPROXY_LOGLEVEL                     Log level
SMTPROXY_HANDSHAKE_LOGLEVEL           Handshake Log level
```
