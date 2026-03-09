\# Environment Variables





```



Variable                            Description                        Default                         Current

--------------------------------------------------------------------------------------------------------------------------------------------

SMTPROXY\_SERVER\_NAME                Server name                        <OS Hostname>                   mailprox.example.com

SMTPROXY\_LISTEN\_ADDR                STARTTLS listen address            :25                             :25

SMTPROXY\_TLS\_LISTEN\_ADDR            TLS      listen address            :465                            :465

SMTPROXY\_METRICS\_LISTEN\_ADDR        Metrics  listen address            :9100                           :9100

SMTPROXY\_ROUTING\_MODE               Routing mode                       local-first                     local-first

SMTPROXY\_LOCAL\_UPSTREAMS            Local  upstreams                   :25                             \[mail.example.com:25]

SMTPROXY\_REMOTE\_UPSTREAMS           Remote upstreams                   \[]                              \[]

SMTPROXY\_DNS\_SERVERS                DNS Servers                        \[]                              \[1.2.3.4]

SMTPROXY\_REQUIRE\_TLS                Require TLS                        true                            true

SMTPROXY\_UPSTREAM\_STARTTLS          Upstream use STARTTLS              true                            true

SMTPROXY\_UPSTREAM\_REQUIRE\_TLS       Upstream requires TLS              true                            true

SMTPROXY\_UPSTREAM\_TLS               Upstream implicit TLS              false                           false

SMTPROXY\_TLS13\_ONLY                 TLS13 only                         false                           false

SMTPROXY\_UPSTREAM\_TLS13\_ONLY        Upstream TLS13 only                false                           false

SMTPROXY\_SKIP\_CERT\_VALIDATION       Skip cert validation               false                           false

SMTPROXY\_SEND\_XCLIENT               XCLIENT to signal IP               false                           false

SMTPROXY\_MAX\_CONNECTIONS            Maximum sessions                   1000                            1000

SMTPROXY\_TRUSTED\_ROOT\_FILE          Trusted root file                  <System trust store>            \[]

SMTPROXY\_CERT\_DIR                   Certificate directory              /tls                            /tls

SMTPROXY\_MICROCA\_CURVE\_NAME         Optional MicroCA CurveName         \[]                              \[]

SMTPROXY\_CLIENT\_TIMEOUT             Client timeout (sec)               120                             2m0s

SMTPROXY\_SHUTDOWN\_SECONDS           Max shutdown time (sec)            60                              60

SMTPROXY\_CERT\_UPDATE\_CHECK\_SECONDS  Cert Update Check (sec)            300                             300

SMTPROXY\_LOGLEVEL                   Log level                          ERROR                           ERROR

SMTPROXY\_HANDSHAKE\_LOGLEVEL         Handshake Log level                NONE                            NONE



Routing mode values:

&nbsp; \[local-first|failover|loadbalance]



Log level values:

&nbsp; 3=NONE 4=ERROR 5=INFO 6=VERBOSE 7=DEBUG





```



