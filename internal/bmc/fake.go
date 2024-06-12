// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package bmc

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
)

func RegisterFake() {
	registerBMC(fakeBMC)
}

var fakeGlobalState struct {
	sync.RWMutex
	s map[string]fakeState
}

type fakeState map[string]fakeMachine

type fakeMachine struct {
	power Power
	led   LED
}

func fakeBMC(tags map[string]string, host string, port int32, creds Credentials, exp time.Time) BMC {
	if host == "" {
		return &FakeBMC{}
	}

	fakeGlobalState.Lock()
	defer fakeGlobalState.Unlock()
	if fakeGlobalState.s == nil {
		fakeGlobalState.s = make(map[string]fakeState)
	}
	_, ok := fakeGlobalState.s[host]
	if !ok {
		fakeGlobalState.s[host] = fakeState{
			uuid.NewSHA1(uuid.NameSpaceOID, []byte(host)).String(): fakeMachine{
				power: PowerOff,
				led:   LEDOff,
			},
		}
	}

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

func (b *FakeBMC) Credentials() (Credentials, time.Time) {
	return b.creds, b.exp
}

func (b *FakeBMC) Ping(_ context.Context) error {
	return nil
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
	fakeGlobalState.RLock()
	defer fakeGlobalState.RUnlock()
	s, ok := fakeGlobalState.s[b.host]
	if !ok {
		return Info{}, fmt.Errorf("fake host has no state: %s", b.host)
	}

	machines := make([]Machine, 0, len(s))
	for id := range s {
		machines = append(machines, Machine{
			UUID:         id,
			Manufacturer: "Fake",
			SKU:          "Fake-0",
			SerialNumber: "1",
			Power:        s[id].power,
			LocatorLED:   s[id].led,
		})
	}

	return Info{
		Type:            TypeMachine,
		Manufacturer:    "Fake",
		SerialNumber:    "0",
		FirmwareVersion: "1",
		Machines:        machines,
	}, nil
}

func (b *FakeBMC) SetLocatorLED(_ context.Context, machine string, state LED) (LED, error) {
	fakeGlobalState.Lock()
	defer fakeGlobalState.Unlock()
	s, ok := fakeGlobalState.s[b.host]
	if !ok {
		return "", fmt.Errorf("fake host %s has no state", b.host)
	}
	var m fakeMachine
	m, ok = s[machine]
	if !ok {
		return "", fmt.Errorf("fake host %s has no machine %s", b.host, machine)
	}

	m.led = state
	s[machine] = m

	return state, nil
}

func (b *FakeBMC) PowerOn(_ context.Context, machine string) error {
	fakeGlobalState.Lock()
	defer fakeGlobalState.Unlock()
	s, ok := fakeGlobalState.s[b.host]
	if !ok {
		return fmt.Errorf("fake host %s has no state", b.host)
	}
	var m fakeMachine
	m, ok = s[machine]
	if !ok {
		return fmt.Errorf("fake host %s has no machine %s", b.host, machine)
	}

	m.power = PowerOn
	s[machine] = m

	return nil
}

func (b *FakeBMC) PowerOff(_ context.Context, machine string, force bool) error {
	fakeGlobalState.Lock()
	defer fakeGlobalState.Unlock()
	s, ok := fakeGlobalState.s[b.host]
	if !ok {
		return fmt.Errorf("fake host %s has no state", b.host)
	}
	var m fakeMachine
	m, ok = s[machine]
	if !ok {
		return fmt.Errorf("fake host %s has no machine %s", b.host, machine)
	}

	if force || b.tags["fake.power"] != "stuck" {
		m.power = PowerOff
		s[machine] = m
	}

	return nil
}

func (b *FakeBMC) Restart(_ context.Context, machine string, _ bool) error {
	fakeGlobalState.RLock()
	defer fakeGlobalState.RUnlock()
	s, ok := fakeGlobalState.s[b.host]
	if !ok {
		return fmt.Errorf("fake host %s has no state", b.host)
	}
	_, ok = s[machine]
	if !ok {
		return fmt.Errorf("fake host %s has no machine %s", b.host, machine)
	}

	return nil
}
