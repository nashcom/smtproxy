//go:build !proxyproto

package main

import (
        "net"
        "crypto/tls"
)

var gProxyProtocolSupported = false

func createListener(listenAddress string, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    if proxyEnabled == true {
        logLine("Proxy protocol requested but not compiled in (ignored)")
    }

    return net.Listen("tcp", listenAddress)
}


func createTlsListener(listenAddress string, serverTLSConfig *tls.Config, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    if proxyEnabled == true {
        logLine("Proxy protocol requested but not compiled in (ignored)")
    }

    return tls.Listen("tcp", listenAddress, serverTLSConfig)
}
