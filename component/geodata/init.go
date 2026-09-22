package geodata

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var (
	initGeoSite bool
	initGeoIP   int
	initASN     bool

	initGeoSiteMutex sync.Mutex
	initGeoIPMutex   sync.Mutex
	initASNMutex     sync.Mutex

	geoIpEnable   atomic.Bool
	geoSiteEnable atomic.Bool
	asnEnable     atomic.Bool

	geoIpUrl   string
	mmdbUrl    string
	geoSiteUrl string
	asnUrl     string
)

func GeoIpUrl() string {
	return geoIpUrl
}

func SetGeoIpUrl(url string) {
	geoIpUrl = url
}

func MmdbUrl() string {
	return mmdbUrl
}

func SetMmdbUrl(url string) {
	mmdbUrl = url
}

func GeoSiteUrl() string {
	return geoSiteUrl
}

func SetGeoSiteUrl(url string) {
	geoSiteUrl = url
}

func ASNUrl() string {
	return asnUrl
}

func SetASNUrl(url string) {
	asnUrl = url
}

func downloadToPath(url string, path string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func asyncDownloadGeoResource(name, url, path string) {
	log.Infoln("[GeoData] %s async download started", name)
	if err := downloadToPath(url, path); err != nil {
		log.Errorln("[GeoData] Can't download %s: %v", name, err)
		return
	}
	log.Infoln("[GeoData] %s async download completed", name)
}

func InitGeoSite() error {
	geoSiteEnable.Store(true)
	initGeoSiteMutex.Lock()
	defer initGeoSiteMutex.Unlock()
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("[GeoData] GeoSite.dat not found, async download started")
		go asyncDownloadGeoResource("GeoSite.dat", GeoSiteUrl(), C.Path.GeoSite())
		return nil
	}
	if !initGeoSite {
		if err := Verify(C.GeositeName); err != nil {
			log.Warnln("GeoSite.dat invalid, remove and async download: %s", err)
			_ = os.Remove(C.Path.GeoSite())
			go asyncDownloadGeoResource("GeoSite.dat", GeoSiteUrl(), C.Path.GeoSite())
			return nil
		}
		initGeoSite = true
	}
	return nil
}

func InitGeoIP() error {
	geoIpEnable.Store(true)
	initGeoIPMutex.Lock()
	defer initGeoIPMutex.Unlock()
	if GeodataMode() {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("[GeoData] GeoIP.dat not found, async download started")
			go asyncDownloadGeoResource("GeoIP.dat", GeoIpUrl(), C.Path.GeoIP())
			return nil
		}

		if initGeoIP != 1 {
			if err := Verify(C.GeoipName); err != nil {
				log.Warnln("GeoIP.dat invalid, remove and async download: %s", err)
				_ = os.Remove(C.Path.GeoIP())
				go asyncDownloadGeoResource("GeoIP.dat", GeoIpUrl(), C.Path.GeoIP())
				return nil
			}
			initGeoIP = 1
		}
		return nil
	}

	if _, err := os.Stat(C.Path.MMDB()); os.IsNotExist(err) {
		log.Infoln("[GeoData] MMDB not found, async download started")
		go asyncDownloadGeoResource("MMDB", MmdbUrl(), C.Path.MMDB())
		return nil
	}

	if initGeoIP != 2 {
		if !mmdb.Verify(C.Path.MMDB()) {
			log.Warnln("MMDB invalid, remove and async download")
			_ = os.Remove(C.Path.MMDB())
			go asyncDownloadGeoResource("MMDB", MmdbUrl(), C.Path.MMDB())
			return nil
		}
		initGeoIP = 2
	}
	return nil
}

func InitASN() error {
	asnEnable.Store(true)
	initASNMutex.Lock()
	defer initASNMutex.Unlock()
	if _, err := os.Stat(C.Path.ASN()); os.IsNotExist(err) {
		log.Infoln("[GeoData] ASN.mmdb not found, async download started")
		go asyncDownloadGeoResource("ASN.mmdb", ASNUrl(), C.Path.ASN())
		return nil
	}
	if !initASN {
		if !mmdb.Verify(C.Path.ASN()) {
			log.Warnln("ASN invalid, remove and async download")
			_ = os.Remove(C.Path.ASN())
			go asyncDownloadGeoResource("ASN.mmdb", ASNUrl(), C.Path.ASN())
			return nil
		}
		initASN = true
	}
	return nil
}

func GeoIpEnable() bool {
	return geoIpEnable.Load()
}

func GeoSiteEnable() bool {
	return geoSiteEnable.Load()
}

func ASNEnable() bool {
	return asnEnable.Load()
}
