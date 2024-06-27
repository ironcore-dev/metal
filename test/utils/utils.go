// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
)

func GetProjectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.Replace(wd, "/test/e2e", "", -1)
	return wd, nil
}

func GenerateMacAddress(prefix string) (string, error) {
	buf := make([]byte, 3)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("cannot generate MAC address: %w", err)
	}
	mac := fmt.Sprintf("%s%02x%02x%02x", prefix, buf[0], buf[1], buf[2])
	return mac, nil
}

func GenerateIpAddress() (v1alpha1.IPAddr, error) {
	addr, err := GenerateIpAddressString()
	if err != nil {
		return v1alpha1.IPAddr{}, fmt.Errorf("cannot generate IP address: %w", err)
	}
	var ip netip.Addr
	ip, err = netip.ParseAddr(addr)
	if err != nil {
		return v1alpha1.IPAddr{}, fmt.Errorf("cannot parse IP address: %w", err)
	}
	return v1alpha1.IPAddr{
		Net: ip,
	}, nil
}

func GenerateIpAddressString() (string, error) {
	buf := make([]byte, 3)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("cannot generate IP address: %w", err)
	}
	return fmt.Sprintf("10.%d.%d.%d", buf[0], buf[1], buf[2]), nil
}
