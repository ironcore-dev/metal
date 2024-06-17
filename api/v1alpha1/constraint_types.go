// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/resource"
)

// ConstraintSpec contains conditions of constraint that should be applied on resource.
type ConstraintSpec struct {
	// Path is a path to the struct field constraint will be applied to
	// +kubebuilder:validation:Optional
	Path JSONPath `json:"path,omitempty"`
	// Aggregate defines whether collection values should be aggregated
	// for constraint checks, in case if path defines selector for collection
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=avg;sum;min;max;count
	Aggregate AggregateType `json:"agg,omitempty"`
	// Equal contains an exact expected value
	// +kubebuilder:validation:Optional
	Equal *ConstraintValSpec `json:"eq,omitempty"`
	// NotEqual contains an exact not expected value
	// +kubebuilder:validation:Optional
	NotEqual *ConstraintValSpec `json:"neq,omitempty"`
	// LessThan contains an highest expected value, exclusive
	// +kubebuilder:validation:Optional
	LessThan *resource.Quantity `json:"lt,omitempty"`
	// LessThan contains an highest expected value, inclusive
	// +kubebuilder:validation:Optional
	LessThanOrEqual *resource.Quantity `json:"lte,omitempty"`
	// LessThan contains an lowest expected value, exclusive
	// +kubebuilder:validation:Optional
	GreaterThan *resource.Quantity `json:"gt,omitempty"`
	// GreaterThanOrEqual contains an lowest expected value, inclusive
	// +kubebuilder:validation:Optional
	GreaterThanOrEqual *resource.Quantity `json:"gte,omitempty"`
}

func (in *ConstraintSpec) MatchSingleValue(value *reflect.Value) (bool, error) {
	// We do not have special constraints for nil and/or empty values
	// so returning false for now if the value is nil
	if value.Kind() == reflect.Ptr && value.IsNil() {
		return false, nil
	}

	if in.Equal != nil {
		r, err := in.Equal.Compare(value)
		if err != nil {
			return false, err
		}
		return r == 0, nil
	}
	if in.NotEqual != nil {
		r, err := in.NotEqual.Compare(value)
		if err != nil {
			return false, err
		}
		return r != 0, nil
	}

	matches := true
	q, err := valueToQuantity(value)
	if err != nil {
		return false, err
	}
	if in.GreaterThanOrEqual != nil {
		r := q.Cmp(*in.GreaterThanOrEqual)
		matches = r >= 0
	}
	if in.GreaterThan != nil {
		r := q.Cmp(*in.GreaterThan)
		matches = matches && (r > 0)
	}
	if in.LessThanOrEqual != nil {
		r := q.Cmp(*in.LessThanOrEqual)
		matches = matches && (r <= 0)
	}
	if in.LessThan != nil {
		r := q.Cmp(*in.LessThan)
		matches = matches && (r < 0)
	}

	return matches, nil
}

func (in *ConstraintSpec) MatchMultipleValues(aggregateType AggregateType, values []reflect.Value) (bool, error) {
	if aggregateType == "" {
		for _, value := range values {
			matches, err := in.MatchSingleValue(&value)
			if err != nil {
				return false, err
			}
			if !matches {
				return false, nil
			}
		}
		return true, nil
	}

	agg, err := makeAggregate(aggregateType, values)
	if err != nil {
		return false, errors.Wrapf(err, "unable to compute aggregate %s", aggregateType)
	}

	if in.Equal != nil {
		return agg.Cmp(*in.Equal.Numeric) == 0, nil
	}
	if in.NotEqual != nil {
		return agg.Cmp(*in.NotEqual.Numeric) != 0, nil
	}

	matches := true
	if in.GreaterThanOrEqual != nil {
		r := agg.Cmp(*in.GreaterThanOrEqual)
		matches = r >= 0
	}
	if in.GreaterThan != nil {
		r := agg.Cmp(*in.GreaterThan)
		matches = matches && (r > 0)
	}
	if in.LessThanOrEqual != nil {
		r := agg.Cmp(*in.LessThanOrEqual)
		matches = matches && (r <= 0)
	}
	if in.LessThan != nil {
		r := agg.Cmp(*in.LessThan)
		matches = matches && (r < 0)
	}

	return matches, nil
}
