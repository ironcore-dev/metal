// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package internal

func NilOrEqual[T comparable](x, y *T) bool {
	return (x == nil && y == nil) || (x != nil && y != nil && *x == *y)
}
