//go:build proxyproto

package main

import (
        "net"
        "time"
        "crypto/tls"
        proxyproto "github.com/pires/go-proxyproto"
)

var gProxyProtocolSupported = true

func createListener(listenAddress string, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    base, err := net.Listen("tcp", listenAddress)
    if err != nil {
        logMsg("Cannot listen on port %v", listenAddress)
        return nil, err
    }

    trusted, err := parseCIDRs(trustedProxies)
    if err != nil {
        logMsg("Invalid Trusted Proxy configuration on TLS port: %v", trustedProxies)
        return nil, err
    }

    pl := &proxyproto.Listener{
        Listener: base,
        ReadHeaderTimeout: 2 * time.Second,

        Policy: func(addr net.Addr) (proxyproto.Policy, error) {
            ip := extractIP(addr)

            if !ipInNets(ip, trusted) {
                logMsg("Untrusted proxy %s based on %v", ip, trusted)
                return proxyproto.REJECT, nil
            }

            return proxyproto.USE, nil
        },
    }

    return pl, nil
}


func createTlsListener(listenAddress string, serverTLSConfig *tls.Config, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    base, err := tls.Listen("tcp", listenAddress, serverTLSConfig)
    if err != nil {
        logMsg("Cannot listen on TLS port %v", listenAddress)
        return nil, err
    }

    trusted, err := parseCIDRs(trustedProxies)
    if err != nil {
        logMsg("Invalid Trusted Proxy configuration on TLS port: %v", trustedProxies)
        return nil, err
    }

    pl := &proxyproto.Listener{
        Listener: base,
        ReadHeaderTimeout: 2 * time.Second,

        Policy: func(addr net.Addr) (proxyproto.Policy, error) {
            ip := extractIP(addr)

            if !ipInNets(ip, trusted) {
                logMsg("TLS Untrusted proxy %s based on %v", ip, trusted)
                return proxyproto.REJECT, nil
            }

            return proxyproto.USE, nil
        },
    }

    return pl, nil
}

