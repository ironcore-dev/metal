package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/ssa"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewInventoryReconciler() (*InventoryReconciler, error) {
	return &InventoryReconciler{}, nil
}

type InventoryReconciler struct {
	client.Client
}

func (r *InventoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var inventory metalv1alpha1.Inventory
	if err := r.Get(ctx, req.NamespacedName, &inventory); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Inventory: %w", err))
	}
	if !inventory.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.reconcile(ctx, inventory)
}

func (r *InventoryReconciler) reconcile(ctx context.Context, inventory metalv1alpha1.Inventory) error {
	machines := &metalv1alpha1.MachineList{}
	if err := r.List(ctx, machines); err != nil {
		return err
	}
	idx := slices.IndexFunc(machines.Items, func(machine metalv1alpha1.Machine) bool {
		return machine.Spec.UUID == inventory.Name
	})
	if idx == -1 {
		return nil
	}

	machine := machines.Items[idx].DeepCopy()
	machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace)

	if machine.Spec.InventoryRef == nil {
		machineSpecApply := metalv1alpha1apply.MachineSpec().
			WithPower(metalv1alpha1.PowerOff).
			WithInventoryRef(v1.LocalObjectReference{Name: inventory.Name})
		machineApply = machineApply.WithSpec(machineSpecApply)
	} else {
		sizeLabels := make(map[string]string)
		for k, v := range machine.GetLabels() {
			if !strings.HasPrefix(k, MachineSizeLabelPrefix) {
				continue
			}
			sizeLabels[k] = v
		}
		if len(sizeLabels) != 0 {
			machineApply = machineApply.WithLabels(sizeLabels)
		}
		machineSpecApply := metalv1alpha1apply.MachineSpec().
			WithInventoryRef(v1.LocalObjectReference{Name: inventory.Name})
		machineApply = machineApply.WithSpec(machineSpecApply)
	}
	return r.Patch(ctx, machine, ssa.Apply(machineApply), client.FieldOwner(MachineFieldOwner), client.ForceOwnership)
}

func (r *InventoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Inventory{}).
		Complete(r)
}
