// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package bmc

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

type BMC interface {
	Type() string
	Tags() map[string]string
	Credentials() (Credentials, time.Time)
	EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error
	Connect(ctx context.Context) error
	CreateUser(ctx context.Context, creds Credentials, tempPassword string) error
	DeleteUsers(ctx context.Context, regex *regexp.Regexp) error
	ReadInfo(ctx context.Context) (Info, error)
}

type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Info struct {
	Type            Typ
	Manufacturer    string
	SerialNumber    string
	FirmwareVersion string
	Console         string
	Machines        []Machine
}

type Typ string

const (
	TypeMachine Typ = "Machine"
	TypeSwitch  Typ = "Switch"
	TypeRouter  Typ = "Router"
)

type Machine struct {
	UUID         string
	Manufacturer string
	SKU          string
	SerialNumber string
	Power        Power
	LocatorLED   LED
}

type Power string

const (
	PowerOn  Power = "On"
	PowerOff Power = "Off"
)

type LED string

const (
	LEDOn       LED = "On"
	LEDOff      LED = "Off"
	LEDBlinking LED = "Blinking"
)

type LEDControl interface {
	SetLocatorLED(ctx context.Context, state LED) (LED, error)
}

type PowerControl interface {
	PowerOn(ctx context.Context) error
	PowerOff(ctx context.Context, force bool) error
}

type RestartControl interface {
	Restart(ctx context.Context, force bool) error
}

func NewBMC(typ string, tags map[string]string, host string, port int32, creds Credentials, exp time.Time) (BMC, error) {
	newFunc, ok := bmcs[typ]
	if !ok {
		return nil, fmt.Errorf("BMC of type %s is not supported", typ)
	}

	return newFunc(tags, host, port, creds, exp), nil
}

var (
	bmcs = make(map[string]newBMCFunc)
)

type newBMCFunc func(tags map[string]string, host string, port int32, creds Credentials, exp time.Time) BMC

func registerBMC(newFunc newBMCFunc) {
	bmcs[newFunc(nil, "", 0, Credentials{}, time.Time{}).Type()] = newFunc
}
