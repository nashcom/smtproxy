// smtproxy - SMTP Proxy in Go / metrics routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "sync/atomic"
)

func writeMetricString(w *bufio.Writer, name string, help string, metricType string, value string, labels map[string]string) {

    w.WriteString("# HELP ")
    w.WriteString(name)
    w.WriteByte(' ')
    w.WriteString(help)
    w.WriteByte('\n')

    w.WriteString("# TYPE ")
    w.WriteString(name)
    w.WriteByte(' ')
    w.WriteString(metricType)
    w.WriteByte('\n')

    w.WriteString(name)

    if len(labels) > 0 {
        w.WriteByte('{')

        first := true
        for k, v := range labels {
            if !first {
                w.WriteByte(',')
            }

            w.WriteString(k)
            w.WriteString(`="`)
            w.WriteString(v)
            w.WriteByte('"')

            first = false
        }

        w.WriteByte('}')
    }

    w.WriteByte(' ')
    w.WriteString(value)
    w.WriteByte('\n')
}

func writeMetric(w *bufio.Writer, name string, help string, metricType string, value int64, labels map[string]string) {

    writeMetricString(
        w,
        name,
        help,
        metricType,
        strconv.FormatInt(value, 10),
        labels,
    )
}

func writeMetricFloat(w *bufio.Writer, name string, help string, metricType string, value float64, labels map[string]string) {

    writeMetricString(
        w,
        name,
        help,
        metricType,
        strconv.FormatFloat(value, 'f', -1, 64),
        labels,
    )
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {

    // Load values first
    activeConnections := atomic.LoadInt64(&gActiveConnections)
    totalConnections  := atomic.LoadInt64(&gTotalConnections)

    w.Header().Set("Content-Type", "text/plain; version=0.0.4")

    bw := bufio.NewWriter(w)

    writeMetric(
        bw,
        "smtpproxy_build",
        fmt.Sprintf("Build number (version %s, platform %s)", gVersionStr, gBuildPlatform),
        "gauge",
        VersionBuild,
        nil,
    )

    writeMetric(
        bw,
        "smtpproxy_go_build",
        fmt.Sprintf("Go runtime build number (%s)", gGoVersion),
        "gauge",
        gGoVersionBuild,
        nil,
    )

    writeMetric(
        bw,
        "smtpproxy_active_connections",
        "Current active SMTP sessions",
        "gauge",
        activeConnections,
        nil,
    )

    writeMetric(
        bw,
        "smtpproxy_connections_total",
        "Total SMTP connections",
        "counter",
        totalConnections,
        nil,
    )

    writeMetric(
        bw,
        "smtpproxy_tls_cert_expiry_timestamp_seconds",
        "Earliest TLS certificate expiration time (Unix epoch seconds)",
        "gauge",
        gCertExpiration,
        nil,
    )

    writeMetric(
        bw,
        "smtpproxy_config_errors_total",
        "Total configuration errors detected during startup or reload",
        "counter",
        gConfigErrors,
        nil,
    )


    if gRdnsResolver != nil {

        rdnsCacheHitsTotal       := gRdnsResolver.cacheHits.Load()
        rdnsCacheMissesTotal     := gRdnsResolver.cacheMisses.Load()
        rdnsDnsQueriesTotal      := gRdnsResolver.dnsQueries.Load()
        rdnsDnsTimeoutsTotal     := gRdnsResolver.dnsTimeouts.Load()
        rdnsDnsErrorsTotal       := gRdnsResolver.dnsErrors.Load()
        rdnsDnsQuerySecondsTotal := float64(gRdnsResolver.dnsQueryTime.Load()) / 1e9


        writeMetric(
            bw,
            "smtpproxy_rdns_cache_hits_total",
            "Total reverse DNS cache hits",
            "counter",
            rdnsCacheHitsTotal,
            nil,
        )

        writeMetric(
            bw,
            "smtpproxy_rdns_cache_misses_total",
            "Total reverse DNS cache misses",
            "counter",
            rdnsCacheMissesTotal,
            nil,
        )

        writeMetric(
            bw,
            "smtpproxy_rdns_dns_queries_total",
            "Total reverse DNS DNS queries performed",
            "counter",
            rdnsDnsQueriesTotal,
            nil,
        )

        writeMetric(
            bw,
            "smtpproxy_rdns_dns_timeouts_total",
            "Total reverse DNS DNS query timeouts",
            "counter",
            rdnsDnsTimeoutsTotal,
            nil,
        )

        writeMetric(
            bw,
            "smtpproxy_rdns_dns_errors_total",
            "Total reverse DNS DNS query errors",
            "counter",
            rdnsDnsErrorsTotal,
            nil,
        )

        writeMetricFloat(
            bw,
            "smtpproxy_rdns_dns_query_seconds_total",
            "Total time spent performing reverse DNS lookups",
            "counter",
            rdnsDnsQuerySecondsTotal,
            nil,
        )
    }

    bw.Flush()
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
