package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caCertFile = "mitm-ca.crt"
	caKeyFile  = "mitm-ca.key"
)

// CA holds the root certificate used to sign per-host leaf certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreateCA loads the CA from dir, generating it on first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read CA key: %w", err)
		}
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil {
			return nil, fmt.Errorf("invalid CA pem")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &CA{
			cert:    cert,
			key:     key,
			certPEM: certPEM,
			leafKey: leafKey,
			cache:   make(map[string]*tls.Certificate),
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Mihomo MITM CA",
			Organization: []string{"Mihomo MITM"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// PEM returns the root CA certificate in PEM form.
func (ca *CA) PEM() []byte {
	return ca.certPEM
}

// Fingerprint returns the SHA-256 fingerprint of the root CA.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.cert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	return strings.Join(parts, ":")
}

// GetCertificate implements tls.Config.GetCertificate.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeDomain(hello.ServerName)
	if host == "" {
		return nil, fmt.Errorf("missing server name")
	}
	return ca.certificateForHost(host)
}

func (ca *CA) certificateForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &ca.leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  ca.leafKey,
	}
	ca.cache[host] = cert
	return cert, nil
}
