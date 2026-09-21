package geodata

import (
	"fmt"
	"path/filepath"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
)

type loader struct {
	LoaderImplementation
}

func (l *loader) LoadGeoSite(list string) ([]*router.Domain, error) {
	return l.LoadSiteByPath(C.GeositeName, list)
}

func (l *loader) LoadGeoIP(country string) ([]*router.CIDR, error) {
	// ★ 防御: 不直接使用全局 C.GeoipName(可能被过期状态污染),
	// 每次通过 C.Path.GeoIP() 重新扫描获取实际存在的 GeoIP.dat 文件名
	return l.LoadIPByPath(filepath.Base(C.Path.GeoIP()), country)
}

var loaders map[string]func() LoaderImplementation

func RegisterGeoDataLoaderImplementationCreator(name string, loader func() LoaderImplementation) {
	if loaders == nil {
		loaders = map[string]func() LoaderImplementation{}
	}
	loaders[name] = loader
}

func getGeoDataLoaderImplementation(name string) (LoaderImplementation, error) {
	if geoLoader, ok := loaders[name]; ok {
		return geoLoader(), nil
	}
	return nil, fmt.Errorf("unable to locate GeoData loader %s", name)
}

func GetGeoDataLoader(name string) (Loader, error) {
	loadImpl, err := getGeoDataLoaderImplementation(name)
	if err == nil {
		return &loader{loadImpl}, nil
	}
	return nil, err
}
