//go:build proxyproto

package main

import (
        "log"
        "net"
        "time"
        "crypto/tls"
        proxyproto "github.com/pires/go-proxyproto"
)

var gProxyProtocolSupported = true

func createListener(listenAddress string, proxyEnabled bool, trustedProxies []string) (net.Listener, error) {

    base, err := net.Listen("tcp", listenAddress)
    if err != nil {
        log.Printf("Cannot listen on port %v\n", listenAddress)
        return nil, err
    }

    trusted, err := parseCIDRs(trustedProxies)
    if err != nil {
        log.Printf("Invalid Trusted Proxy configuration on TLS port: %v\n", trustedProxies)
        return nil, err
    }

    pl := &proxyproto.Listener{
        Listener: base,
        ReadHeaderTimeout: 2 * time.Second,

        Policy: func(addr net.Addr) (proxyproto.Policy, error) {
            ip := extractIP(addr)

            if !ipInNets(ip, trusted) {
                log.Printf("Untrusted proxy %s based on %v\n", ip, trusted)
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
        log.Printf("Cannot listen on TLS port %v\n", listenAddress)
        return nil, err
    }

    trusted, err := parseCIDRs(trustedProxies)
    if err != nil {
        log.Printf("Invalid Trusted Proxy configuration on TLS port: %v\n", trustedProxies)
        return nil, err
    }

    pl := &proxyproto.Listener{
        Listener: base,
        ReadHeaderTimeout: 2 * time.Second,

        Policy: func(addr net.Addr) (proxyproto.Policy, error) {
            ip := extractIP(addr)

            if !ipInNets(ip, trusted) {
                log.Printf("TLS Untrusted proxy %s based on %v", ip, trusted)
                return proxyproto.REJECT, nil
            }

            return proxyproto.USE, nil
        },
    }

    return pl, nil
}

