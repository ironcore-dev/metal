// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package bmc

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

func RegisterFake() {
	registerBMC(fakeBMC)
}

func fakeBMC(tags map[string]string, host string, port int32, creds Credentials, exp time.Time) BMC {
	return &FakeBMC{
		tags:  tags,
		host:  host,
		port:  port,
		creds: creds,
		exp:   exp,
	}
}

type FakeBMC struct {
	tags  map[string]string
	host  string
	port  int32
	creds Credentials
	exp   time.Time
}

func (b *FakeBMC) Type() string {
	return "Redfish"
}

func (b *FakeBMC) Tags() map[string]string {
	return b.tags
}

func (b *FakeBMC) LEDControl() LEDControl {
	return b
}

func (b *FakeBMC) PowerControl() PowerControl {
	return b
}

func (b *FakeBMC) RestartControl() RestartControl {
	return b
}

func (b *FakeBMC) Credentials() (Credentials, time.Time) {
	return b.creds, b.exp
}

func (b *FakeBMC) EnsureInitialCredentials(_ context.Context, defaultCreds []Credentials, tempPassword string) error {
	if len(defaultCreds) == 0 {
		return fmt.Errorf("no default credentials to try")
	}

	b.creds = defaultCreds[0]
	b.creds.Password = tempPassword
	return nil
}

func (b *FakeBMC) Connect(_ context.Context) error {
	return nil
}

func (b *FakeBMC) CreateUser(_ context.Context, creds Credentials, _ string) error {
	b.creds = creds
	b.exp = time.Time{}
	return nil
}

func (b *FakeBMC) DeleteUsers(_ context.Context, _ *regexp.Regexp) error {
	return nil
}

func (b *FakeBMC) ReadInfo(_ context.Context) (Info, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return Info{}, fmt.Errorf("cannot generate UUID: %w", err)
	}

	return Info{
		Type:            TypeMachine,
		Manufacturer:    "Fake",
		SerialNumber:    "0",
		FirmwareVersion: "1",
		Machines: []Machine{
			{
				UUID:         id.String(),
				Manufacturer: "Fake",
				SKU:          "Fake-0",
				SerialNumber: "1",
				Power:        PowerOn,
				LocatorLED:   LEDOff,
			},
		},
	}, nil
}

func (b *FakeBMC) SetLocatorLED(_ context.Context, state LED) (LED, error) {
	return state, nil
}

func (b *FakeBMC) PowerOn(_ context.Context) error {
	return nil
}

func (b *FakeBMC) PowerOff(_ context.Context, _ bool) error {
	return nil
}

func (b *FakeBMC) Restart(_ context.Context, _ bool) error {
	return nil
}
