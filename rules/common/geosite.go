package common

import (
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	"github.com/metacubex/mihomo/component/geodata/router"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type GEOSITE struct {
	Base
	country     string
	adapter     string
	recodeSize  int
	lazyErrOnce sync.Once
}

func (gs *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (gs *GEOSITE) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	return gs.MatchDomain(metadata.RuleHost()), gs.adapter
}

// MatchDomain implements C.DomainMatcher
func (gs *GEOSITE) MatchDomain(domain string) bool {
	if len(domain) == 0 {
		return false
	}
	matcher, err := gs.GetDomainMatcher()
	if err != nil {
		gs.lazyErrOnce.Do(func() {
			log.Warnln("[GeoSite] %s lazy load failed (rule will never match): %v", gs.country, err)
		})
		return false
	}
	return matcher.ApplyDomain(domain)
}

func (gs *GEOSITE) Adapter() string {
	return gs.adapter
}

func (gs *GEOSITE) Payload() string {
	return gs.country
}

func (gs *GEOSITE) GetDomainMatcher() (router.DomainMatcher, error) {
	matcher, err := geodata.LoadGeoSiteMatcher(gs.country)
	if err != nil {
		return nil, fmt.Errorf("load GeoSite data error, %w", err)
	}
	return matcher, nil
}

func (gs *GEOSITE) GetRecodeSize() int {
	if matcher, err := gs.GetDomainMatcher(); err == nil {
		return matcher.Count()
	}
	return 0
}

func NewGEOSITE(country string, adapter string) (*GEOSITE, error) {
	if err := geodata.InitGeoSite(); err != nil {
		log.Errorln("can't initial GeoSite: %s", err)
		return nil, err
	}

	geoSite := &GEOSITE{
		Base:    Base{},
		country: country,
		adapter: adapter,
	}

	// ★ 懒加载(对齐 ProjectClash 的 lazy init 思路): 不在配置解析阶段解码 geosite,
	//   冷启动的大头(.dat 解码 + 匹配树构建)推迟到首次命中;
	//   startGeoDataPreload 会在启动后空闲时段主动预热配置里用到的分类,
	//   避免把成本丢到首个请求上。分类名非法时在首次命中处告警(而非拒绝整份配置)。
	log.Infoln("GeoSite rule %s => %s registered (lazy load)", country, adapter)

	return geoSite, nil
}

var _ C.Rule = (*GEOSITE)(nil)
