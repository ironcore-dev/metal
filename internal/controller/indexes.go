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
	var err error

	err = indexer.IndexField(ctx, &metalv1alpha1.Machine{}, MachineSpecOOBRefName, func(obj client.Object) []string {
		machine := obj.(*metalv1alpha1.Machine)
		if machine.Spec.OOBRef.Name == "" {
			return nil
		}
		return []string{machine.Spec.OOBRef.Name}
	})
	if err != nil {
		return fmt.Errorf("cannot index field %s: %w", MachineSpecOOBRefName, err)
	}

	err = indexer.IndexField(ctx, &metalv1alpha1.MachineClaim{}, MachineClaimSpecMachineRefName, func(obj client.Object) []string {
		claim := obj.(*metalv1alpha1.MachineClaim)
		if claim.Spec.MachineRef == nil || claim.Spec.MachineRef.Name == "" {
			return nil
		}
		return []string{claim.Spec.MachineRef.Name}
	})
	if err != nil {
		return fmt.Errorf("cannot index field %s: %w", MachineClaimSpecMachineRefName, err)
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

	err = indexer.IndexField(ctx, &metalv1alpha1.OOBSecret{}, OOBSecretSpecMACAddress, func(obj client.Object) []string {
		secret := obj.(*metalv1alpha1.OOBSecret)
		if secret.Spec.MACAddress == "" {
			return nil
		}
		return []string{secret.Spec.MACAddress}
	})
	if err != nil {
		return fmt.Errorf("cannot index field %s: %w", OOBSecretSpecMACAddress, err)
	}

	return nil
}
