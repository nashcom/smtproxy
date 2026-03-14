
package main

import (
    "context"
    "errors"
    "fmt"
    "net"
    "strings"
    "time"
)

func NewRdnsResolver(dnsServers []string) *RdnsResolver {

    var resolver *net.Resolver

    if len(dnsServers) == 0 || (len(dnsServers) == 1 && dnsServers[0] == DNS_RESOLVER_SYSTEM) {

        resolver = net.DefaultResolver

    } else {

        dialer := &net.Dialer{
            Timeout: 10 * time.Second,
        }

        resolver = &net.Resolver{
            PreferGo: true,
            Dial: func(ctx context.Context, network, address string) (net.Conn, error) {

                server := dnsServers[time.Now().UnixNano()%int64(len(dnsServers))]

                if !strings.Contains(server, ":") {
                    server = net.JoinHostPort(server, "53")
                }

                return dialer.DialContext(ctx, network, server)
            },
        }
    }

    return &RdnsResolver{
        resolver:    resolver,
        cache:       make(map[string]cacheEntry),
        positiveTTL: gDNSpositiveTTL,
        negativeTTL: gDNSnegativeTTL,
    }
}

func (r *RdnsResolver) cacheLookup(ip string) (string, bool, bool) {

    now := time.Now()

    r.cacheMutex.RLock()
    entry, ok := r.cache[ip]
    r.cacheMutex.RUnlock()

    if !ok || now.After(entry.expire) {
        return "", false, false
    }

    r.cacheHits.Add(1)

    if entry.negative {
        return "", true, true
    }

    return entry.host, true, false
}

func (r *RdnsResolver) cacheStore(ip string, host string, negative bool) {

    expire := r.positiveTTL
    if negative {
        expire = r.negativeTTL
    }

    entry := cacheEntry{
        host:     host,
        expire:   time.Now().Add(expire),
        negative: negative,
    }

    r.cacheMutex.Lock()
    r.cache[ip] = entry
    r.cacheMutex.Unlock()
}

func (r *RdnsResolver) Lookup(ip string) (string, bool) {

    if gDNScacheEnabled {

        if host, ok, negative := r.cacheLookup(ip); ok {

            if negative {
                return "", false
            }

            return host, true
        }

        r.cacheMisses.Add(1)
    }

    r.dnsQueries.Add(1)

    start:= time.Now()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    names, err := r.resolver.LookupAddr(ctx, ip)

    duration := time.Since(start)
    r.dnsQueryTime.Add(duration.Nanoseconds())

    if err != nil {

        if errors.Is(err, context.DeadlineExceeded) {
            r.dnsTimeouts.Add(1)
        } else {
            r.dnsErrors.Add(1)
        }

        r.cacheStore(ip, "", true)
        return "", false
    }

    if len(names) == 0 {

        r.dnsErrors.Add(1)

        r.cacheStore(ip, "", true)
        return "", false
    }

    host := strings.TrimSuffix(names[0], ".")

    if gDNScacheEnabled {
        r.cacheStore(ip, host, false)
    }

    return host, true
}

func NewRbldnsResolver(server string) *RblDnsResolver {

    var resolver *net.Resolver

    if server == DNS_RESOLVER_SYSTEM {

        resolver = net.DefaultResolver

    } else {

        resolver = &net.Resolver{
            PreferGo: true,
            Dial: func(ctx context.Context, network, address string) (net.Conn, error) {

                d := net.Dialer{
                    Timeout: 10 * time.Second,
                }

                return d.DialContext(ctx, network, server)
            },
        }
    }

    return &RblDnsResolver{
        resolver: resolver,
    }
}

func reverseIPv4(ip net.IP) string {
    parts := strings.Split(ip.String(), ".")
    for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
        parts[i], parts[j] = parts[j], parts[i]
    }
    return strings.Join(parts, ".")
}

func reverseIPv6(ip net.IP) string {
    ip = ip.To16()

    var nibbles []string

    for i := len(ip) - 1; i >= 0; i-- {
        nibbles = append(nibbles,
            fmt.Sprintf("%x", ip[i]&0x0f),
            fmt.Sprintf("%x", ip[i]>>4),
        )
    }

    return strings.Join(nibbles, ".")
}

func buildQueryRBL(ip net.IP, zone string) string {

    if ip.To4() != nil {
        return reverseIPv4(ip) + "." + zone
    }

    return reverseIPv6(ip) + "." + zone
}

func (r * RblDnsResolver) checkRBL(ip net.IP, zone string) (bool, []net.IP, error) {

    query := buildQueryRBL(ip, zone)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    r.dnsQueries.Add(1)
    start:= time.Now()

    addrs, err := r.resolver.LookupIP(ctx, "ip4", query)

    duration := time.Since(start)
    r.dnsQueryTime.Add(duration.Nanoseconds())

    if err != nil {

        if errors.Is(err, context.DeadlineExceeded) {
            r.dnsTimeouts.Add(1)

        } else if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {

            r.dnsNotFound.Add(1)
            return false, nil, nil
        }

        r.dnsErrors.Add(1)
        return false, nil, err
    }

    var ips []net.IP

    for _, a := range addrs {
        ips = append(ips, a)
    }

    if len(ips) > 0 {

        ip4 := ips[0].To4()

        if ip4 != nil && ip4[0] == 127 {

            switch ip4[3] {

            case 254:
                return false, ips, nil

            case 255:
                return false, ips, nil
            }
        }
    }

    r.dnsFound.Add(1)
    return true, ips, nil
}
