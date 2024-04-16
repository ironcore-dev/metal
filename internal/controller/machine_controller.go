// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"slices"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/patch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update

const (
	MachineFieldOwner string = "metal.ironcore.dev/machine"
	MachineFinalizer  string = "metal.ironcore.dev/machine"

	MachineInitializedConditionType       = "Initialized"
	MachineInitializedConditionPosReason  = "MachineInitialized"
	MachineInitializedConditionNegReason  = "MachineNotInitialized"
	MachineInitializedConditionNegMessage = "Machine not initialized"
	MachineInitializedConditionPosMessage = "Machine initialized"

	MachineInventoriedConditionType       = "Inventoried"
	MachineInventoriedConditionPosReason  = "MachineInventoried"
	MachineInventoriedConditionNegReason  = "MachineNotInventoried"
	MachineInventoriedConditionNegMessage = "Machine not inventoried"
	MachineInventoriedConditionPosMessage = "Machine inventoried"

	MachineClassifiedConditionType       = "Classified"
	MachineClassifiedConditionPosReason  = "MachineClassified"
	MachineClassifiedConditionNegReason  = "MachineNotClassified"
	MachineClassifiedConditionNegMessage = "Machine not classified"
	MachineClassifiedConditionPosMessage = "Machine classified"

	MachineReadyConditionType       = "Ready"
	MachineReadyConditionPosReason  = "MachineReady"
	MachineReadyConditionNegReason  = "MachineNotReady"
	MachineReadyConditionNegMessage = "Machine not ready"
	MachineReadyConditionPosMessage = "Machine ready"
)

func NewMachineReconciler() (*MachineReconciler, error) {
	return &MachineReconciler{}, nil
}

// MachineReconciler reconciles a Machine object
type MachineReconciler struct {
	client.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MachineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var machine metalv1alpha1.Machine
	if err := r.Get(ctx, req.NamespacedName, &machine); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Machine: %w", err))
	}
	if !machine.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	return r.reconcile(ctx, &machine)
}

func (r *MachineReconciler) reconcile(ctx context.Context, machine *metalv1alpha1.Machine) (ctrl.Result, error) {
	prerequisites, err := r.fillConditions(ctx, machine)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !prerequisites {
		return ctrl.Result{}, nil
	}

	if err := r.initialize(ctx, machine); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.inventorize(ctx, machine); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *MachineReconciler) initialize(ctx context.Context, machine *metalv1alpha1.Machine) error {
	var (
		oob       metalv1alpha1.OOB
		condition *metav1.Condition
	)
	applyStatus := metalv1alpha1apply.MachineStatus().WithConditions(machine.Status.Conditions...)
	idx := slices.IndexFunc(applyStatus.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineInitializedConditionType
	})
	baseCondition := applyStatus.Conditions[idx]
	condition = baseCondition.DeepCopy()

	err := r.Get(ctx, types.NamespacedName{Name: machine.Spec.OOBRef.Name, Namespace: machine.Namespace}, &oob)
	if err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = MachineInitializedConditionNegReason
		condition.Message = fmt.Sprintf("Cannot get OOB object: %v", err)
		return r.Status().Patch(
			ctx, machine, patch.Apply(applyStatus), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
	}
	applyStatus = applyStatus.
		WithManufacturer(oob.Status.Manufacturer).
		WithSerialNumber(oob.Status.SerialNumber).
		WithSKU(oob.Status.SKU)
	condition.Status = metav1.ConditionTrue
	condition.Reason = MachineInitializedConditionPosReason
	condition.Message = MachineInitializedConditionPosMessage
	if baseCondition.Status != condition.Status {
		condition.LastTransitionTime = metav1.Now()
		condition.ObservedGeneration = machine.Generation
	}
	applyStatus.Conditions[idx] = *condition

	return r.Status().Patch(
		ctx, machine, patch.Apply(applyStatus), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
}

func (r *MachineReconciler) inventorize(ctx context.Context, machine *metalv1alpha1.Machine) error {
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType && condition.Status == metav1.ConditionTrue
	}); idx >= 0 {
		return nil
	}

	return nil
}

func (r *MachineReconciler) fillConditions(ctx context.Context, machine *metalv1alpha1.Machine) (bool, error) {
	prerequisites := true
	applyStatus := metalv1alpha1apply.MachineStatus()
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInitializedConditionType
	}); idx < 0 {
		prerequisites = false
		applyStatus = metalv1alpha1apply.MachineStatus().WithConditions(metav1.Condition{
			Type:               MachineInitializedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: machine.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineInitializedConditionNegReason,
			Message:            MachineInitializedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType
	}); idx < 0 {
		prerequisites = false
		applyStatus = metalv1alpha1apply.MachineStatus().WithConditions(metav1.Condition{
			Type:               MachineInventoriedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: machine.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineInventoriedConditionNegReason,
			Message:            MachineInventoriedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineClassifiedConditionType
	}); idx < 0 {
		prerequisites = false
		applyStatus = metalv1alpha1apply.MachineStatus().WithConditions(metav1.Condition{
			Type:               MachineClassifiedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: machine.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineClassifiedConditionNegReason,
			Message:            MachineClassifiedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineReadyConditionType
	}); idx < 0 {
		prerequisites = false
		applyStatus = metalv1alpha1apply.MachineStatus().WithConditions(metav1.Condition{
			Type:               MachineReadyConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: machine.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineReadyConditionNegReason,
			Message:            MachineReadyConditionNegMessage,
		})
	}
	if machine.Status.State == "" {
		prerequisites = false
		applyStatus = metalv1alpha1apply.MachineStatus().WithState(metalv1alpha1.MachineStateInitial)
	}
	if !prerequisites {
		return false, r.Status().Patch(
			ctx, machine, patch.Apply(applyStatus), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
	}
	return true, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Machine{}).
		Complete(r)
}
