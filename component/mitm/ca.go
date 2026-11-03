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
	dir     string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// caRegistry 记录进程内 CA 实例, 供内存压力时清理 leaf 证书内存缓存(磁盘缓存保留)。
var caRegistry sync.Map

// ClearLeafCaches 清理所有 CA 的内存 leaf 缓存, 返回释放条目数。
func ClearLeafCaches() int {
	n := 0
	caRegistry.Range(func(key, _ any) bool {
		if ca, ok := key.(*CA); ok {
			n += ca.clearMemoryCache()
		}
		return true
	})
	return n
}

func (ca *CA) clearMemoryCache() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	n := len(ca.cache)
	ca.cache = make(map[string]*tls.Certificate)
	return n
}

// LoadOrCreateCA loads the CA from dir, generating it on first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA dir %q: %w", dir, err)
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read CA key %q: %w", keyPath, err)
		}
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil {
			return nil, fmt.Errorf("invalid CA pem (cert block %v, key block %v)", certBlock != nil, keyBlock != nil)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA cert %q: %w", certPath, err)
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			parsed, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("parse CA key %q (SEC1: %v; PKCS8: %v)", keyPath, err, parseErr)
			}
			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("CA key is not ECDSA (got %T)", parsed)
			}
			key = ecKey
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate CA leaf key: %w", err)
		}
		return &CA{
			cert:    cert,
			key:     key,
			certPEM: certPEM,
			leafKey: leafKey,
			dir:     dir,
			cache:   make(map[string]*tls.Certificate),
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read CA cert %q: %w", certPath, err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ca, err := createAndWriteCA(dir, certPath, keyPath)
		if err == nil {
			return ca, nil
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return nil, fmt.Errorf("generate CA failed after 3 attempts: %w", lastErr)
}

func createAndWriteCA(dir, certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA private key (ECDSA P-256): %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial (rand.Reader): %w", err)
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
		return nil, fmt.Errorf("create self-signed CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CA cert %q: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key %q: %w", keyPath, err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA leaf key: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		leafKey: leafKey,
		dir:     dir,
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
	caRegistry.Store(ca, struct{}{})
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}
	// 磁盘 leaf 缓存(对齐 ProjectClash ModuleLeafStore): 重启后免重新签发
	if cert, ok := ca.loadLeafCert(host); ok {
		ca.cache[host] = cert
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
	ca.saveLeafCert(host, der)
	ca.cache[host] = cert
	return cert, nil
}

func (ca *CA) leafCachePath(host string) string {
	sum := sha256.Sum256([]byte(host))
	return filepath.Join(ca.dir, "leaves", hex.EncodeToString(sum[:16])+".pem")
}

// loadLeafCert 读取磁盘缓存的 leaf 证书(证书+私钥), 过期则视为未命中。
func (ca *CA) loadLeafCert(host string) (*tls.Certificate, bool) {
	if ca.dir == "" {
		return nil, false
	}
	data, err := os.ReadFile(ca.leafCachePath(host))
	if err != nil {
		return nil, false
	}
	var leaf *x509.Certificate
	var key *ecdsa.PrivateKey
	rest := data
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		switch block.Type {
		case "CERTIFICATE":
			if parsed, parseErr := x509.ParseCertificate(block.Bytes); parseErr == nil {
				leaf = parsed
			}
		case "EC PRIVATE KEY":
			if parsed, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
				key = parsed
			}
		}
	}
	if leaf == nil || key == nil {
		return nil, false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, false
	}
	return &tls.Certificate{
		Certificate: [][]byte{leaf.Raw, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, true
}

// saveLeafCert 原子写入 leaf 证书与私钥; 失败不影响本次握手。
func (ca *CA) saveLeafCert(host string, der []byte) {
	if ca.dir == "" {
		return
	}
	leafDir := filepath.Join(ca.dir, "leaves")
	if err := os.MkdirAll(leafDir, 0o700); err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.leafKey)
	if err != nil {
		return
	}
	payload := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	path := ca.leafCachePath(host)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}
