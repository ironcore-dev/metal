// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"net/netip"
)

type Prefix struct {
	netip.Prefix `json:"-"`
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) UnmarshalJSON(b []byte) error {
	if len(b) == 4 && string(b) == "null" {
		p.Prefix = netip.Prefix{}
		return nil
	}

	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	var pr netip.Prefix
	pr, err = netip.ParsePrefix(str)
	if err != nil {
		return err
	}

	p.Prefix = pr
	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}

	return json.Marshal(p.String())
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) ToUnstructured() interface{} {
	if p.IsZero() {
		return nil
	}

	return p.String()
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) DeepCopyInto(out *Prefix) {
	*out = *p
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) DeepCopy() *Prefix {
	return &Prefix{p.Prefix}
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) IsValid() bool {
	return p != nil && p.Prefix.IsValid()
}

//goland:noinspection GoMixedReceiverTypes
func (p *Prefix) IsZero() bool {
	return p == nil || !p.Prefix.IsValid()
}

//goland:noinspection GoMixedReceiverTypes
func (p Prefix) OpenAPISchemaType() []string {
	return []string{"string"}
}

//goland:noinspection GoMixedReceiverTypes
func (p Prefix) OpenAPISchemaFormat() string {
	return "prefix"
}
