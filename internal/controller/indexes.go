// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
)

func CreateIndexes(ctx context.Context, mgr manager.Manager) error {
	indexer := mgr.GetFieldIndexer()

	err := indexer.IndexField(ctx, &metalv1alpha1.MachineClaim{}, MachineClaimSpecMachineRef, func(obj client.Object) []string {
		claim := obj.(*metalv1alpha1.MachineClaim)
		if claim.Spec.MachineRef == nil || claim.Spec.MachineRef.Name == "" {
			return nil
		}
		return []string{claim.Spec.MachineRef.Name}
	})
	if err != nil {
		return fmt.Errorf("cannot index field %s: %w", MachineClaimSpecMachineRef, err)
	}

	err = indexer.IndexField(ctx, &metalv1alpha1.OOB{}, OOBSpecMACAddress, func(obj client.Object) []string {
		oob := obj.(*metalv1alpha1.OOB)
		if oob.Spec.MACAddress == "" {
			return nil
		}
		return []string{oob.Spec.MACAddress}
	})
	if err != nil {
		return fmt.Errorf("cannot index field %s: %w", OOBSpecMACAddress, err)
	}

	return nil
}
