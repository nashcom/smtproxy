// smtproxy - SMTP Proxy in Go / Certificate routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rsa"
    "crypto/rand"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
    "encoding/pem"
    "errors"
    "fmt"
    "log"
    "math/big"
    "os"
    "net"
    "strings"
    "time"
)

func dumpCertificateChain(description string, chain []*x509.Certificate, showDetails bool) {

    // Only prints basic information from leaf only if showDetails is false

    fmt.Printf("\n")
    fmt.Printf("---------------------------------------------------\n")

    if showDetails {
        fmt.Printf("Certificates(%d) %s\n", len(chain), description)
    } else {
        fmt.Printf("Leaf Certificate %s\n", description)
    }

    fmt.Printf("---------------------------------------------------\n")
    fmt.Printf("\n")

    for i, cert := range chain {

        if showDetails {
            fmt.Printf("----- Certificate %d -----\n\n", i)

            if i == 0 {
                showInfo("Type", "Leaf")
            } else {
                showInfo("Type", "Intermediate/CA")
            }
        }

        showInfo("Subject", cert.Subject.String())
        showInfo("Issuer", cert.Issuer.String())
        showInfo("Publicy key", formatPublicKey (cert))

        if len(cert.DNSNames) > 0 {
            showInfo("DNS SANs", strings.Join(cert.DNSNames, " "))
        }

        if len(cert.IPAddresses) > 0 {
            ips := make([]string, len(cert.IPAddresses))
            for i, ip := range cert.IPAddresses {
                ips[i] = ip.String()
            }

            showInfo("IP SANs", strings.Join(ips, " "))
        }

        if len(cert.EmailAddresses) > 0 {
            showInfo("Email SANs", strings.Join(cert.EmailAddresses, " "))
        }

        if len(cert.URIs) > 0 {
            uris := make([]string, len(cert.URIs))
            for i, uri := range cert.URIs {
                uris[i] = uri.String()
            }

            showInfo("URI SANs", strings.Join(uris, " "))
        }

        showInfo("Key Usage", formatKeyUsage(cert.KeyUsage))
        showInfo("Ext Key Usage", formatExtKeyUsage(cert.ExtKeyUsage))

        if showDetails {
            showInfo("Serial", cert.SerialNumber.String())
        }
        showInfo("SHA256", formatFingerprintSHA256(cert))

        if showDetails {

            showInfo("SHA1", formatFingerprintSHA1(cert))

            if len(cert.SubjectKeyId) > 0 {
                showInfo("SKI", formatHexWithColon(cert.SubjectKeyId))
            }

            if len(cert.AuthorityKeyId) > 0 {
                showInfo("AKI", formatHexWithColon(cert.AuthorityKeyId))
            }

            showInfo("NotBefore", cert.NotBefore.Format(time.RFC3339))
        }

        showInfo("NotAfter", cert.NotAfter.Format(time.RFC3339))

        fmt.Printf("\n")

        // Only show leaf cert
        if false == showDetails {
            return
        }
    }
}

func formatFingerprintSHA256(cert *x509.Certificate) string {
    sum := sha256.Sum256(cert.Raw)
    return formatHexWithColon(sum[:])
}

func formatFingerprintSHA1(cert *x509.Certificate) string {
    sum := sha1.Sum(cert.Raw)
    return formatHexWithColon(sum[:])
}

func formatHexWithColon(data []byte) string {
    hexStr := hex.EncodeToString(data)
    var result string

    for i := 0; i < len(hexStr); i += 2 {
        if i > 0 {
            result += ":"
        }
        result += hexStr[i : i+2]
    }

    return result
}

func tlsCertsToX509(certs []tls.Certificate) ([]*x509.Certificate, error) {
    count := 0

    for _, c := range certs {
        count += len(c.Certificate)
    }

    chain := make([]*x509.Certificate, 0, count)

    for _, c := range certs {
        for _, der := range c.Certificate {
            cert, err := x509.ParseCertificate(der)
            if err != nil {
                return nil, err
            }

            chain = append(chain, cert)
        }
    }

    return chain, nil
}

func formatKeyUsage(usage x509.KeyUsage) string {

    var list []string

    if usage&x509.KeyUsageDigitalSignature != 0 {
        list = append(list, "DigitalSignature")
    }
    if usage&x509.KeyUsageContentCommitment != 0 {
        list = append(list, "ContentCommitment")
    }
    if usage&x509.KeyUsageKeyEncipherment != 0 {
        list = append(list, "KeyEncipherment")
    }
    if usage&x509.KeyUsageDataEncipherment != 0 {
        list = append(list, "DataEncipherment")
    }
    if usage&x509.KeyUsageKeyAgreement != 0 {
        list = append(list, "KeyAgreement")
    }
    if usage&x509.KeyUsageCertSign != 0 {
        list = append(list, "CertSign")
    }
    if usage&x509.KeyUsageCRLSign != 0 {
        list = append(list, "CRLSign")
    }
    if usage&x509.KeyUsageEncipherOnly != 0 {
        list = append(list, "EncipherOnly")
    }
    if usage&x509.KeyUsageDecipherOnly != 0 {
        list = append(list, "DecipherOnly")
    }

    if len(list) == 0 {
        return "None"
    }

    return strings.Join(list, ", ")
}

func formatExtKeyUsage(usages []x509.ExtKeyUsage) string {

    var list []string

    for _, u := range usages {

        switch u {

        case x509.ExtKeyUsageServerAuth:
            list = append(list, "ServerAuth")

        case x509.ExtKeyUsageClientAuth:
            list = append(list, "ClientAuth")

        case x509.ExtKeyUsageCodeSigning:
            list = append(list, "CodeSigning")

        case x509.ExtKeyUsageEmailProtection:
            list = append(list, "EmailProtection")

        case x509.ExtKeyUsageTimeStamping:
            list = append(list, "TimeStamping")

        case x509.ExtKeyUsageOCSPSigning:
            list = append(list, "OCSPSigning")

        default:
            list = append(list, "Unknown")
        }
    }

    if len(list) == 0 {
        return "None"
    }

    return strings.Join(list, ", ")
}

func fetchChainViaHTTP(host string, port string, serverName string, timeout time.Duration) ([]*x509.Certificate, error) {
    dialer := &net.Dialer{
        Timeout: timeout,
    }

    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    conf := &tls.Config{
        ServerName:         serverName, // overridden SNI
        InsecureSkipVerify: true,       // manual verification later
    }

    conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), conf)
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
    }

    state := conn.ConnectionState()

    if len(state.PeerCertificates) == 0 {
        return nil, errors.New("no certificates received")
    }

    return state.PeerCertificates, nil
}



func ECDSACurveFromName(name string) (elliptic.Curve, error) {

    switch strings.ToUpper(name) {

    case "P256":
        return elliptic.P256(), nil

    case "P384":
        return elliptic.P384(), nil

    case "P521":
        return elliptic.P521(), nil

    default:
        return nil, fmt.Errorf("unsupported ECDSA curve: %s", name)
    }
}


func formatPublicKey(cert *x509.Certificate) string {

    switch cert.PublicKeyAlgorithm {

    case x509.RSA:

        if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
            return fmt.Sprintf("RSA %d bit", k.N.BitLen())
        }

        return "RSA"

    case x509.ECDSA:

        if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
            return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
        }

        return "ECDSA"

    case x509.Ed25519:
        return "Ed25519"

    default:
        return "Unknown"
    }
}


func ReadPrivateKeyFromBytes(pemBytes []byte) (crypto.Signer, error) {

    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }

    if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {

        signer, ok := key.(crypto.Signer)
        if !ok {
            return nil, fmt.Errorf("unsupported private key type")
        }

        return signer, nil
    }

    if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
        return key, nil
    }

    if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
        return key, nil
    }

    return nil, fmt.Errorf("unsupported private key format: %s", block.Type)
}


func GenerateRootCertificate(NameRootCA string, privateKey crypto.Signer) ([]byte, []byte, error) {

    NotBefore := time.Now()
    NotAfter := NotBefore.AddDate(1, 0, 0)

    SerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, nil, fmt.Errorf("Failed to generate serial number: %v", err)
    }

    Template := x509.Certificate{
        SerialNumber: SerialNumber,
        Subject: pkix.Name{
            CommonName: NameRootCA,
        },

        NotBefore: NotBefore,
        NotAfter:  NotAfter,

        KeyUsage: x509.KeyUsageCRLSign |
            x509.KeyUsageCertSign |
            x509.KeyUsageDigitalSignature,

        IsCA:                  true,
        BasicConstraintsValid: true,
    }

    CertDER, err := x509.CreateCertificate(
        rand.Reader,
        &Template,
        &Template,
        privateKey.Public(),
        privateKey,
    )

    if err != nil {
        return nil, nil, fmt.Errorf("Failed to create certificate: %v", err)
    }

    CertPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: CertDER,
    })

    KeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, nil, fmt.Errorf("Failed to marshal private key: %v", err)
    }

    KeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: KeyBytes,
    })

    return CertPEM, KeyPEM, nil
}


func GenerateLeafCertificate(

    szCommonName string,
    szNameSAN string,
    szIPAddress string,
    privateKey crypto.Signer,
    RootCert *x509.Certificate,
    rootKey crypto.Signer,
) ([]byte, []byte, error) {

    NotBefore := time.Now()
    NotAfter := NotBefore.AddDate(1, 0, 0)

    SerialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, nil, fmt.Errorf("Failed to generate serial number: %v", err)
    }

    ExtensionSAN := []string{szNameSAN}

    IPList := []net.IP{}

    if szIPAddress != "" {
        if ip := net.ParseIP(szIPAddress); ip != nil {
            IPList = append(IPList, ip)
        }
    }

    Template := x509.Certificate{
        SerialNumber: SerialNumber,
        Subject: pkix.Name{
            CommonName: szCommonName,
        },

        NotBefore: NotBefore,
        NotAfter:  NotAfter,

        KeyUsage: x509.KeyUsageKeyEncipherment |
            x509.KeyUsageDigitalSignature,

        BasicConstraintsValid: true,

        ExtKeyUsage: []x509.ExtKeyUsage{
            x509.ExtKeyUsageServerAuth,
            x509.ExtKeyUsageClientAuth,
        },

        DNSNames:    ExtensionSAN,
        IPAddresses: IPList,
    }

    CertDER, err := x509.CreateCertificate(
        rand.Reader,
        &Template,
        RootCert,
        privateKey.Public(),
        rootKey,
    )

    if err != nil {
        return nil, nil, fmt.Errorf("Failed to create leaf certificate: %v", err)
    }

    CertPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: CertDER,
    })

    KeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return nil, nil, fmt.Errorf("Failed to marshal private key: %v", err)
    }

    KeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: KeyBytes,
    })

    return CertPEM, KeyPEM, nil
}


func GenerateRSAKey(bits int) (crypto.Signer, error) {

    priv, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, fmt.Errorf("failed to generate RSA private key: %v", err)
    }

    return priv, nil
}


func GenerateECDSAKey(curveName string) (crypto.Signer, error) {

    curve, err := ECDSACurveFromName(curveName)
    if err != nil {
        return nil, err
    }

    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate ECDSA private key: %v", err)
    }

    return priv, nil
}

func CreateCertAndKey(
    nameSAN string,
    commonName string,
    nameRootCA string,
    rootKeyFileName string,
    rootCertFileName string,
    leafKeyFileName string,
    leafCertFileName string,
    curveName string,
    updateCert bool) {

    var err error
    var RootPrivateKey crypto.Signer
    var RootCertPEM []byte
    var RootKeyPEM []byte

    if fileExists(rootCertFileName) && fileExists(rootKeyFileName) {

        log.Printf("Using existing root CA: %s", rootCertFileName)

        RootCertPEM, err = os.ReadFile(rootCertFileName)
        if err != nil {
            log.Fatalf("Failed to read root certificate: %v", err)
        }

        RootKeyPEM, err = os.ReadFile(rootKeyFileName)
        if err != nil {
            log.Fatalf("Failed to read root key: %v", err)
        }

        RootPrivateKey, err = ReadPrivateKeyFromBytes(RootKeyPEM)
        if err != nil {
            log.Fatalf("Failed to parse root private key: %v", err)
        }

    } else {

        log.Printf("Generating new root CA")

        if curveName == "" {
            RootPrivateKey, err = GenerateRSAKey(4096)
        } else {
            RootPrivateKey, err = GenerateECDSAKey(curveName)
        }

        if err != nil {
            log.Fatalf("Failed to generate root private key: %v", err)
        }

        RootCertPEM, RootKeyPEM, err = GenerateRootCertificate(nameRootCA, RootPrivateKey)
        if err != nil {
            log.Fatalf("Failed to generate root certificate: %v", err)
        }

        os.WriteFile(rootCertFileName, RootCertPEM, 0600)
        os.WriteFile(rootKeyFileName, RootKeyPEM, 0600)
    }

    block, _ := pem.Decode(RootCertPEM)
    if block == nil {
        log.Fatalf("Failed to decode root certificate")
    }

    RootCert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        log.Fatalf("Failed to parse root certificate: %v", err)
    }

    var LeafPrivateKey crypto.Signer
    var LeafKeyPEM []byte

    if fileExists(leafKeyFileName) {

        LeafKeyPEM, err = os.ReadFile(leafKeyFileName)
        if err != nil {
            log.Fatalf("Failed to read leaf key: %v", err)
        }

        LeafPrivateKey, err = ReadPrivateKeyFromBytes(LeafKeyPEM)
        if err != nil {
            log.Fatalf("Failed to parse leaf key: %v", err)
        }

    } else {

        if curveName == "" {
            LeafPrivateKey, err = GenerateRSAKey(4096)
        } else {
            LeafPrivateKey, err = GenerateECDSAKey(curveName)
        }

        if err != nil {
            log.Fatalf("Failed to generate leaf private key: %v", err)
        }

        KeyBytes, _ := x509.MarshalPKCS8PrivateKey(LeafPrivateKey)

        LeafKeyPEM = pem.EncodeToMemory(&pem.Block{
            Type:  "PRIVATE KEY",
            Bytes: KeyBytes,
        })

        os.WriteFile(leafKeyFileName, LeafKeyPEM, 0600)
    }

    if !updateCert && fileExists(leafCertFileName) {
        log.Printf("Leaf certificate already exists: %s", leafCertFileName)
        return
    }

    log.Printf("Generating leaf certificate")

    LeafCertPEM, _, err := GenerateLeafCertificate(
        commonName,
        nameSAN,
        "",
        LeafPrivateKey,
        RootCert,
        RootPrivateKey,
    )

    if err != nil {
        log.Fatalf("Failed to generate leaf certificate: %v", err)
    }

    szCertChain := string(LeafCertPEM) + "\n" + string(RootCertPEM)

    os.WriteFile(leafCertFileName, []byte(szCertChain), 0600)

    log.Println("Leaf certificate created or updated")
}
