package resource

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

var ErrRemoteFetchDisabled = errors.New("remote fetch disabled (frontend-managed)")

type LocalOnlyVehicle struct {
	Inner P.Vehicle
}

func (l *LocalOnlyVehicle) Type() P.VehicleType        { return l.Inner.Type() }
func (l *LocalOnlyVehicle) Path() string                { return l.Inner.Path() }
func (l *LocalOnlyVehicle) Url() string                 { return l.Inner.Url() }
func (l *LocalOnlyVehicle) Proxy() string               { return l.Inner.Proxy() }
func (l *LocalOnlyVehicle) Write(buf []byte) error      { return l.Inner.Write(buf) }
func (l *LocalOnlyVehicle) Read(_ context.Context, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	return nil, oldHash, ErrRemoteFetchDisabled
}
