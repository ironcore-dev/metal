// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/ssa"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	InventoryFieldManager = "metal.ironcore.dev/inventory-controller"
	defaultAggregateName  = "default"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories/finalizers,verbs=update

func NewInventoryReconciler(systemNamespace string) (*InventoryReconciler, error) {
	return &InventoryReconciler{systemNamespace: systemNamespace}, nil
}

type InventoryReconciler struct {
	client.Client

	systemNamespace string
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
	if err := r.ensureAggregate(ctx); err != nil {
		return err
	}
	return r.reconcileMachine(ctx, inventory)
}

func (r *InventoryReconciler) ensureAggregate(ctx context.Context) error {
	key := types.NamespacedName{Name: defaultAggregateName, Namespace: r.systemNamespace}
	aggregate := metalv1alpha1.Aggregate{}
	err := r.Get(ctx, key, &aggregate)
	if apierrors.IsNotFound(err) {
		return r.createAggregate(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed to get Aggregate: %w", err)
	}
	return nil
}

func (r *InventoryReconciler) reconcileMachine(ctx context.Context, inventory metalv1alpha1.Inventory) error {
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

	if err := r.setControllerReference(ctx, machine, &inventory); err != nil {
		return err
	}

	sizeLabels := make(map[string]string)
	for k, v := range inventory.GetLabels() {
		if !strings.HasPrefix(k, MachineSizeLabelPrefix) {
			continue
		}
		sizeLabels[k] = v
	}
	if len(sizeLabels) != 0 {
		machineApply = machineApply.WithLabels(sizeLabels)
	}

	if machine.Spec.InventoryRef == nil {
		machineSpecApply := metalv1alpha1apply.MachineSpec().
			WithPower(metalv1alpha1.PowerOff).
			WithInventoryRef(corev1.LocalObjectReference{Name: inventory.Name}).
			WithBootConfigurationRef(corev1.LocalObjectReference{})
		machineApply = machineApply.WithSpec(machineSpecApply)
		return r.Patch(
			ctx, machine, ssa.Apply(machineApply), client.FieldOwner(InventoryFieldManager), client.ForceOwnership)
	} else {
		machineSpecApply := metalv1alpha1apply.MachineSpec().
			WithPower(machine.Spec.Power).
			WithInventoryRef(corev1.LocalObjectReference{Name: inventory.Name})
		machineApply = machineApply.WithSpec(machineSpecApply)
		return r.Patch(
			ctx, machine, ssa.Apply(machineApply), client.FieldOwner(InventoryFieldManager), client.ForceOwnership)
	}
}

func (r *InventoryReconciler) setControllerReference(ctx context.Context, machine, inventory client.Object) error {
	owners := inventory.GetOwnerReferences()
	if slices.ContainsFunc(owners, func(ref metav1.OwnerReference) bool {
		return ref.Name == machine.GetName()
	}) {
		return nil
	}

	if err := ctrl.SetControllerReference(machine, inventory, r.Scheme()); err != nil {
		return err
	}
	existing := metav1.GetControllerOf(inventory)
	owner := metav1apply.OwnerReference().
		WithAPIVersion(existing.APIVersion).
		WithKind(existing.Kind).
		WithName(existing.Name).
		WithUID(existing.UID).
		WithController(*existing.Controller).
		WithBlockOwnerDeletion(*existing.BlockOwnerDeletion)
	inventoryApply := metalv1alpha1apply.Inventory(inventory.GetName(), inventory.GetNamespace()).
		WithOwnerReferences(owner)
	return r.Patch(
		ctx, inventory, ssa.Apply(inventoryApply), client.FieldOwner(InventoryFieldManager), client.ForceOwnership)
}

func (r *InventoryReconciler) createAggregate(ctx context.Context) error {
	aggregate := &metalv1alpha1.Aggregate{
		ObjectMeta: metav1.ObjectMeta{Name: defaultAggregateName, Namespace: r.systemNamespace},
	}

	aggregateSpecApply := metalv1alpha1apply.AggregateSpec()
	aggregatesList := []*metalv1alpha1apply.AggregateItemApplyConfiguration{
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.CountAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.blocks[*]")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("blocks.count")),
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.SumAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.blocks[*].size")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("blocks.capacity")),
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.CountAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.cpus[*]")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("cpus.sockets")),
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.SumAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.cpus[*].cores")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("cpus.cores")),
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.SumAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.cpus[*].siblings")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("cpus.threads")),
		metalv1alpha1apply.AggregateItem().
			WithAggregate(metalv1alpha1.CountAggregateType).
			WithSourcePath(*metalv1alpha1.JSONPathFromString("spec.nics[*]")).
			WithTargetPath(*metalv1alpha1.JSONPathFromString("nics.count")),
	}
	aggregateSpecApply = aggregateSpecApply.WithAggregates(aggregatesList...)
	aggregateApply := metalv1alpha1apply.Aggregate(defaultAggregateName, r.systemNamespace).
		WithSpec(aggregateSpecApply)
	return r.Patch(
		ctx, aggregate, ssa.Apply(aggregateApply), client.FieldOwner(InventoryFieldManager), client.ForceOwnership)
}

func (r *InventoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Inventory{}).
		Complete(r)
}
