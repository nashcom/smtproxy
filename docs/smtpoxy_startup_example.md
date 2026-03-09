
# Example statup including configuration output

```
./smtproxyctl.sh run -static
smtproxy
smtproxy
092292139d7c7d8a3e5c8a923c82966b21e861b5642452d63784d3eed20ea73c

2026/03/09 14:56:17 Creating MicroCA in /tls
2026/03/09 14:56:17 Generating new root CA
2026/03/09 14:56:17 Generating leaf certificate
2026/03/09 14:56:17 Leaf certificate created or updated

---------------------------------------------------
Certificates(1) server.crt
---------------------------------------------------

----- Certificate 0 -----

Type           :  Leaf
Subject        :  CN=nsh-t14.localdomain
Issuer         :  CN=smtproxy-MicroCA
Publicy key    :  ECDSA P-521
DNS SANs       :  nsh-t14.localdomain
Key Usage      :  DigitalSignature, KeyEncipherment
Ext Key Usage  :  ServerAuth, ClientAuth
Serial         :  220352846963626795194833963470574459155
SHA256         :  28:c7:34:97:96:e5:0d:be:c4:cf:1e:aa:39:f1:0a:07:02:8b:17:dc:81:30:75:ab:92:63:4c:ce:5b:f9:9f:f3
SHA1           :  2f:cb:6f:3d:5d:b0:dd:cd:cc:f6:43:42:da:55:92:87:f6:e9:dd:6e
AKI            :  80:00:c6:5a:25:48:08:17:71:41:cd:43:0f:3c:c1:ea:10:03:bc:da
NotBefore      :  2026-03-09T14:56:17Z
NotAfter       :  2027-03-09T14:56:17Z


SMTP Proxy V0.9.8
-------------------------

Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved.


Variable                            Description                        Default                         Current
--------------------------------------------------------------------------------------------------------------------------------------------
SMTPROXY_SERVER_NAME                Server name                        <OS Hostname>                   mail.example.com
SMTPROXY_LISTEN_ADDR                STARTTLS listen address            :1025                           :25
SMTPROXY_TLS_LISTEN_ADDR            TLS      listen address            :1465                           :465
SMTPROXY_METRICS_LISTEN_ADDR        Metrics  listen address            :9100                           :9100
SMTPROXY_ROUTING_MODE               Routing mode                       local-first                     local-first
SMTPROXY_LOCAL_UPSTREAMS            Local  upstreams                   :25                             [notes.example.com:25]
SMTPROXY_REMOTE_UPSTREAMS           Remote upstreams                   []                              []
SMTPROXY_DNS_SERVERS                DNS Servers                        []                              [10.255.255.254]
SMTPROXY_REQUIRE_TLS                Require TLS                        true                            true
SMTPROXY_UPSTREAM_STARTTLS          Upstream use STARTTLS              true                            true
SMTPROXY_UPSTREAM_REQUIRE_TLS       Upstream requires TLS              true                            true
SMTPROXY_UPSTREAM_TLS               Upstream implicit TLS              false                           false
SMTPROXY_TLS13_ONLY                 TLS13 only                         false                           false
SMTPROXY_UPSTREAM_TLS13_ONLY        Upstream TLS13 only                false                           false
SMTPROXY_SKIP_CERT_VALIDATION       Skip cert validation               false                           false
SMTPROXY_SEND_XCLIENT               XCLIENT to signal IP               false                           true
SMTPROXY_MAX_CONNECTIONS            Maximum sessions                   1000                            1000
SMTPROXY_TRUSTED_ROOT_FILE          Trusted root file                  <System trust store>            []
SMTPROXY_CERT_DIR                   Certificate directory              /tls                            /tls
SMTPROXY_MICROCA_CURVE_NAME         Optional MicroCA CurveName         []                              P521
SMTPROXY_CLIENT_TIMEOUT             Client timeout (sec)               120                             2m0s
SMTPROXY_SHUTDOWN_SECONDS           Max shutdown time (sec)            60                              60
SMTPROXY_CERT_UPDATE_CHECK_SECONDS  Cert Update Check (sec)            300                             300
SMTPROXY_LOGLEVEL                   Log level                          ERROR                           DEBUG
SMTPROXY_HANDSHAKE_LOGLEVEL         Handshake Log level                NONE                            DEBUG

Routing mode values:
  [local-first|failover|loadbalance]

Log level values:
  3=NONE 4=ERROR 5=INFO 6=VERBOSE 7=DEBUG


Runtime
-------------------------

Name           :  Wolfi
ID             :  wolfi
Version        :  20230201
Go version     :  go1.26.1
OS             :  linux
Arch           :  amd64
Platform       :  static
CPUs           :  12
PID            :  1

Trust Store    :  148
Reverse DNS    :  [10.255.255.254]

2026/03/09 14:56:18 Starting listeners ...

2026/03/09 14:56:18 Listening at /metrics   on [:9100]
2026/03/09 14:56:18 Listening with SMTP TLS on [:465]
2026/03/09 14:56:18 Listening with STARTTLS on [:25]
```
