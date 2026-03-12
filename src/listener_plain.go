//go:build !proxyproto

package main

import (
        "log"
        "net"
        "crypto/tls"
)

var gProxyProtocolSupported = false

func createListener(listenAddress string, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    if proxyEnabled == true {
        log.Printf("Proxy protocol requested but not compiled in (ignored)\n")
    }

    return net.Listen("tcp", listenAddress)
}


func createTlsListener(listenAddress string, serverTLSConfig *tls.Config, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    if proxyEnabled == true {
        log.Printf("Proxy protocol requested but not compiled in (ignored)\n")
    }

    return tls.Listen("tcp", listenAddress, serverTLSConfig)
}
