# Environment Variables

The following environment variables are supported and can be added to Docker/Podman containers or Kubernetes Pods


| Variable                             | Description                     | Default                 | Current                |
|--------------------------------------|---------------------------------|-------------------------|------------------------|
| SMTPROXY_SERVER_NAME                 | Server name                     | `<OS Hostname>`         | mailprox.example.com   |
| SMTPROXY_LISTEN_ADDR                 | STARTTLS listen address         | :25                     | :25                    |
| SMTPROXY_TLS_LISTEN_ADDR             | TLS listen address              | :465                    | :465                   |
| SMTPROXY_METRICS_LISTEN_ADDR         | Metrics listen address          | :9100                   | :9100                  |
| SMTPROXY_ROUTING_MODE                | Routing mode                    | local-first             | local-first            |
| SMTPROXY_LOCAL_UPSTREAMS             | Local upstreams                 | :25                     | [mail.example.com:25]  |
| SMTPROXY_REMOTE_UPSTREAMS            | Remote upstreams                | []                      | []                     |
| SMTPROXY_DNS_SERVERS                 | DNS Servers                     | []                      | [1.2.3.4]              |
| SMTPROXY_REQUIRE_TLS                 | Require TLS                     | true                    | true                   |
| SMTPROXY_UPSTREAM_STARTTLS           | Upstream use STARTTLS           | true                    | true                   |
| SMTPROXY_UPSTREAM_REQUIRE_TLS        | Upstream requires TLS           | true                    | true                   |
| SMTPROXY_UPSTREAM_TLS                | Upstream implicit TLS           | false                   | false                  |
| SMTPROXY_TLS13_ONLY                  | TLS13 only                      | false                   | false                  |
| SMTPROXY_UPSTREAM_TLS13_ONLY         | Upstream TLS13 only             | false                   | false                  |
| SMTPROXY_SKIP_CERT_VALIDATION        | Skip cert validation            | false                   | false                  |
| SMTPROXY_SEND_XCLIENT                | XCLIENT to signal IP            | false                   | false                  |
| SMTPROXY_MAX_CONNECTIONS             | Maximum sessions                | 1000                    | 1000                   |
| SMTPROXY_TRUSTED_ROOT_FILE           | Trusted root file               | `<System trust store>`  | []                     |
| SMTPROXY_CERT_DIR                    | Certificate directory           | /tls                    | /tls                   |
| SMTPROXY_MICROCA_CURVE_NAME          | Optional MicroCA CurveName      | []                      | []                     |
| SMTPROXY_CLIENT_TIMEOUT              | Client timeout (sec)            | 120                     | 2m0s                   |
| SMTPROXY_SHUTDOWN_SECONDS            | Max shutdown time (sec)         | 60                      | 60                     |
| SMTPROXY_CERT_UPDATE_CHECK_SECONDS   | Cert Update Check (sec)         | 300                     | 300                    |
| SMTPROXY_LOGLEVEL                    | Log level                       | ERROR                   | ERROR                  |
| SMTPROXY_HANDSHAKE_LOGLEVEL          | Handshake Log level             | NONE                    | NONE                   |


## Routing mode values:

- local-first
- failover
- loadbalance


## Log level

There are five standard log levels from **NONE** to **DEBUG**
Th default log level is **ERROR**.


| Level   | Description |
|---------|-------------|
| NONE    | Log nothing. |
| ERROR   | Log only errors and failures. |
| INFO    | Log important connection, protocol, and TLS state changes. |
| VERBOSE | Log additional operational details useful for tracing normal flow. |
| DEBUG   | Log full debug and protocol trace output, including client/upstream command and response flow. |

