// smtproxy - SMTP Proxy in Go / log routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "log"
    "fmt"
    "io"
    "os"
    "time"
)

func showCfg(description, variableName, defaultValue, currentValue any) {
    logMsg("%-34s  %-34s %-30v  %v", variableName, description, defaultValue, currentValue)
}

func showInfo(description, currentValue any) {
    logMsg("%-15s:  %v", description, currentValue)
}

func (l LogLevel) LowerCaseStr() string {

    switch l {

    case LOG_NONE:
        return "none"

    case LOG_ERROR:
        return "error"

    case LOG_INFO:
        return "info"

    case LOG_VERBOSE:
        return "verbose"

    case LOG_DEBUG:
        return "debug"

    default:
        return "unknown"
    }
}

func logLine(msg string) {

    ts := time.Now().UTC().Format(time.RFC3339)

    if gLogJSON {
        log.Printf(`{"ts":"%s","type":"%s","msg":%q}`, ts, "event", msg)
        return
    }

    log.Println(ts + "   " + msg)
}

func logSpace() {

    if gLogJSON {
        return
    }

    logLine("")
}

func logMsg(format string, args ...any) {
    logLine(fmt.Sprintf(format, args ...))
}

func logFatal(format string, args ...any) {

    logLine(fmt.Sprintf(format, args ...))
    os.Exit(1)
}


// SMTP session logging

func (s *SmtpSession) logf(level LogLevel, format string, args ...any) {

    if ipInNets (s.clientNetIP, s.cfg.IPNetDebugLog) {
        // Special Debug Net Logging

    } else if ipInNets (s.clientNetIP, s.cfg.IPNetExcludeFromLog) {
        // Excluding from log
        return

    } else if level > gLogLevel {
        return
    }

    if level == LOG_ERROR {
        s.isError = true
        s.sessionError = fmt.Sprintf(format, args...)
    }

    if gLogJSON {

        ts := time.Now().UTC().Format(time.RFC3339)

        log.Printf(`{"ts":"%s","type":"%s","level":"%s","id":"%d", "client-ip":"%s", "msg":%q}`,
            ts, "smtp-log", level.LowerCaseStr(), s.sessionID, s.clientIP, fmt.Sprintf(format, args...))
        return
    }

    logMsg("[%08d %s] %s: %s", s.sessionID, s.clientIP, level, fmt.Sprintf(format, args...))
}

func (s *SmtpSession) logNetError(err error, format string, args ...any) {

    level := LOG_ERROR

    if ipInNets (s.clientNetIP, s.cfg.IPNetDebugLog) {
        // Special Debug Net Logging

    } else if ipInNets (s.clientNetIP, s.cfg.IPNetExcludeFromLog) {
        // Excluding from log
        return

    } else  if err == io.EOF {

        // Only log EOF in verbose log and higher
        if gLogLevel < LOG_VERBOSE {
            return
        }

        level = LOG_VERBOSE

    } else {
        s.isError = true
        s.sessionError = fmt.Sprintf(format, args...)
    }

    if gLogJSON {

        ts := time.Now().UTC().Format(time.RFC3339)

        log.Printf(`{"ts":"%s","type":"%s","level":"%s","id":"%d", "client-ip":"%s", "msg":%q}`,
            ts, "smtp-error", level.LowerCaseStr(), s.sessionID, s.clientIP, fmt.Sprintf(format, args...))
        return
    }

    logMsg("[%08d %s] %s: %s", s.sessionID, s.clientIP, level, fmt.Sprintf(format, args...))
}

// Log SMTP Authentication

func (s *SmtpSession) logAuthentication() {

    if gLogJSON {

        ts := time.Now().UTC().Format(time.RFC3339)

        log.Printf(`{"ts":"%s","type":"%s","id":"%d", "client-ip":"%s"}`,
            ts, "blocked-auth", s.sessionID, s.clientIP)
        return
    }

    logMsg("[%08d %s] Connection for IP [%s] blocked due to AUTH attempt", s.sessionID, s.clientIP, s.clientIP)
}

// SMTP session summary

func (s *SmtpSession) logSessionSummary() {

    duration := time.Since(s.sessionStart)
    seconds := duration.Seconds()
    var statusText string
    var mbps float64

    stats.ConnectionsTotal.Add(1)

    if s.isBlockedByRBL {
        stats.ConnectionsRejectedByRBL.Add(1)
    }

    if seconds > 0 {
        mbps = float64(s.bytesClientToUpstream) / 1024 / 1024 / seconds
    }

    if gLogJSON {

        ts := time.Now().UTC().Format(time.RFC3339)

        if s.isError {
            stats.ConnectionsErrors.Add(1)
            statusText = "error"

        } else {
            stats.ConnectionsSuccess.Add(1)
            statusText = "ok"
        }

        stats.TotalBytesWritten.Add(s.bytesClientToUpstream)
        stats.TotalBytesRead.Add(s.bytesUpstreamToClient)


        log.Printf(
            `{"ts":"%s","type":"%s","id":%d,"client_ip":"%s","client_host":"%s","upstream":"%s","duration":%.3f,"bytes_c2u":%d,"bytes_u2c":%d,"mbps":%.3f,"client_tls_mode":"%s","client_tls_version":"%s","client_cipher":"%s","client_curve":"%s","client_resumed":%t,"upstream_tls_mode":"%s","upstream_tls_version":"%s","upstream_cipher":"%s","upstream_curve":"%s","upstream_resumed":%t,"status":"%s","error":%q}`,
            ts,
            "smtp-session",
            s.sessionID,
            s.clientIP,
            s.clientHostName,
            s.upstreamTarget,
            seconds,
            s.bytesClientToUpstream,
            s.bytesUpstreamToClient,
            mbps,

            s.clientTLSMode,
            s.clientTLSVersion,
            s.clientCipher,
            s.clientCurveID,
            s.clientTLSResumed,

            s.upstreamTLSMode,
            s.upstreamTLSVersion,
            s.upstreamCipher,
            s.upstreamCurveID,
            s.upstreamTLSResumed,

            statusText,
            s.sessionError,
        )

        return
    }

    if s.isError {
        statusText = "ERROR: " + s.sessionError
        stats.SessionErrors.Add(1)

    } else {
        statusText = "OK"
    }

    msg := fmt.Sprintf(
        "Session Summary | Duration %.2fs | C->U %s | U->C %s | Avg %.2f MB/s | Client [%s/%s] (%s) -> Upstream [%s] (%s) Status: [%s]",
        seconds,
        formatBytes(s.bytesClientToUpstream),
        formatBytes(s.bytesUpstreamToClient),
        mbps,
        s.clientIP,
        s.clientHostName,
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
        statusText)

    logMsg("[%08d %s] %s: %s", s.sessionID, s.clientIP, LOG_INFO, msg)
}
