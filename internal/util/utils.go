// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"slices"
)

func NilOrEqual[T comparable](x, y *T) bool {
	return (x == nil && y == nil) || (x != nil && y != nil && *x == *y)
}

func Ensure[T any](x *T) *T {
	if x == nil {
		return new(T)
	}
	return x
}

func Set[T comparable](s []T, x T) []T {
	for _, e := range s {
		if e == x {
			return s
		}
	}
	return append(s, x)
}

func Clear[T comparable](s []T, x T) []T {
	for i, e := range s {
		if e == x {
			return slices.Concat(s[:i], s[i+1:])
		}
	}
	return s
}

type PrefixMap[T any] map[string]T

func (m PrefixMap[T]) Get(p string) (T, bool) {
	for i := len(p); i > 0; i-- {
		l, ok := m[p[:i]]
		if ok {
			return l, true
		}
	}
	return *new(T), false
}
