// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Apply(applyConfig interface{}) client.Patch {
	return applyPatch{
		applyConfig: applyConfig,
	}
}

type applyPatch struct {
	applyConfig interface{}
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return json.Marshal(p.applyConfig)
}

func Add(fins []string, fin string) []string {
	for _, f := range fins {
		if f == fin {
			return fins
		}
	}
	return append(fins, fin)
}

func GetCondition(conds []metav1.Condition, typ string) (metav1.Condition, bool) {
	for _, c := range conds {
		if c.Type == typ {
			return c, true
		}
	}
	return metav1.Condition{}, false
}

func SetCondition(conds []metav1.Condition, cond metav1.Condition) ([]metav1.Condition, bool) {
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.Now()
	}

	for i, c := range conds {
		if c.Type == cond.Type {
			if cond.Status == c.Status && cond.Reason == c.Reason && cond.Message == c.Message {
				return conds, false
			}
			return slices.Concat(conds[:i], []metav1.Condition{cond}, conds[i+1:]), true
		}
	}

	return append(conds, cond), true
}

func SetErrorCondition(conds []metav1.Condition, typ string, err error) ([]metav1.Condition, bool) {
	return SetCondition(conds, metav1.Condition{
		Type:    typ,
		Status:  metav1.ConditionFalse,
		Reason:  "Error",
		Message: err.Error(),
	})
}
