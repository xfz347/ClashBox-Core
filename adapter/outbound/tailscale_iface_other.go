//go:build !ohos

package outbound

// 非 OHOS 平台不做额外处理(Android 由 tailscale.go 内既有 anet 兜底逻辑处理)。
const ohosPatchInterfaceGetter = false

func registerOhosInterfaceGetter() {}
