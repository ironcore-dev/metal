// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"slices"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/patch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

	machineApply := r.reconcile(ctx, &machine)
	return ctrl.Result{}, r.Status().Patch(
		ctx, &machine, patch.Apply(machineApply), client.FieldOwner(MachineFieldOwner), client.ForceOwnership)
}

func (r *MachineReconciler) reconcile(ctx context.Context, machine *metalv1alpha1.Machine) *metalv1alpha1apply.MachineApplyConfiguration {
	machineApply := ConvertToApplyConfiguration(machine)
	r.fillConditions(machineApply)
	if err := r.initialize(ctx, machineApply); err != nil {
		log.Error(ctx, err, "failed to initialize machine")
		return machineApply
	}
	if err := r.inventorize(ctx, machineApply); err != nil {
		log.Error(ctx, err, "failed to inventorize machine")
		return machineApply
	}
	if err := r.classify(ctx, machineApply); err != nil {
		log.Error(ctx, err, "failed to classify machine")
		return machineApply
	}

	return machineApply
}

func (r *MachineReconciler) initialize(
	ctx context.Context,
	machineApply *metalv1alpha1apply.MachineApplyConfiguration,
) error {
	var (
		oob       metalv1alpha1.OOB
		condition *metav1.Condition
	)

	applyStatus := machineApply.Status
	idx := slices.IndexFunc(applyStatus.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineInitializedConditionType
	})
	baseCondition := applyStatus.Conditions[idx]
	condition = baseCondition.DeepCopy()

	key := types.NamespacedName{Name: machineApply.Spec.OOBRef.Name, Namespace: *machineApply.Namespace}
	err := r.Get(ctx, key, &oob)
	switch {
	case err != nil:
		condition.Status = metav1.ConditionFalse
		condition.Reason = MachineInitializedConditionNegReason
		condition.Message = fmt.Sprintf("Cannot get OOB object: %v", err)
	case oob.Status.Manufacturer != "" && oob.Status.SerialNumber != "" && oob.Status.SKU != "":
		applyStatus = applyStatus.
			WithManufacturer(oob.Status.Manufacturer).
			WithSerialNumber(oob.Status.SerialNumber).
			WithSKU(oob.Status.SKU)
		condition.Status = metav1.ConditionTrue
		condition.Reason = MachineInitializedConditionPosReason
		condition.Message = MachineInitializedConditionPosMessage
	}
	if baseCondition.Status != condition.Status {
		condition.LastTransitionTime = metav1.Now()
		condition.ObservedGeneration = *machineApply.Generation
	}
	applyStatus.Conditions[idx] = *condition
	machineApply = machineApply.WithStatus(applyStatus)
	return err
}

func (r *MachineReconciler) inventorize(
	ctx context.Context,
	machineApply *metalv1alpha1apply.MachineApplyConfiguration,
) error {
	var (
		inventory metalv1alpha1.Inventory
		condition *metav1.Condition
	)

	applyStatus := machineApply.Status
	idx := slices.IndexFunc(applyStatus.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineInventoriedConditionType
	})
	baseCondition := applyStatus.Conditions[idx]
	condition = baseCondition.DeepCopy()
	key := types.NamespacedName{Name: machineApply.Spec.InventoryRef.Name, Namespace: *machineApply.Namespace}
	err := r.Get(ctx, key, &inventory)
	switch {
	case err != nil:
		condition.Status = metav1.ConditionFalse
		condition.Reason = MachineInventoriedConditionNegReason
		condition.Message = fmt.Sprintf("Cannot get Inventory object: %v", err)
	case len(inventory.Spec.NICs) > 0:
		networkInterfaces := make([]*metalv1alpha1apply.MachineNetworkInterfaceApplyConfiguration, len(inventory.Spec.NICs))
		for _, nic := range inventory.Spec.NICs {
			networkInterfaces = append(networkInterfaces, metalv1alpha1apply.MachineNetworkInterface().
				WithName(nic.Name).WithMacAddress(nic.MACAddress))
		}
		applyStatus = applyStatus.WithNetworkInterfaces(networkInterfaces...)
		condition.Status = metav1.ConditionTrue
		condition.Reason = MachineInventoriedConditionPosReason
		condition.Message = MachineInventoriedConditionPosMessage
	}
	if baseCondition.Status != condition.Status {
		condition.LastTransitionTime = metav1.Now()
		condition.ObservedGeneration = *machineApply.Generation
	}
	applyStatus.Conditions[idx] = *condition
	machineApply = machineApply.WithStatus(applyStatus)
	return err
}

func (r *MachineReconciler) classify(ctx context.Context, machineApply *metalv1alpha1apply.MachineApplyConfiguration) error {
	return nil
}

func (r *MachineReconciler) fillConditions(machineApply *metalv1alpha1apply.MachineApplyConfiguration) {
	statusApply := machineApply.Status
	if idx := slices.IndexFunc(statusApply.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInitializedConditionType
	}); idx < 0 {
		statusApply = statusApply.WithConditions(metav1.Condition{
			Type:               MachineInitializedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: *machineApply.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineInitializedConditionNegReason,
			Message:            MachineInitializedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(statusApply.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType
	}); idx < 0 {
		statusApply = statusApply.WithConditions(metav1.Condition{
			Type:               MachineInventoriedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: *machineApply.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineInventoriedConditionNegReason,
			Message:            MachineInventoriedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(statusApply.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineClassifiedConditionType
	}); idx < 0 {
		statusApply = statusApply.WithConditions(metav1.Condition{
			Type:               MachineClassifiedConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: *machineApply.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineClassifiedConditionNegReason,
			Message:            MachineClassifiedConditionNegMessage,
		})
	}
	if idx := slices.IndexFunc(statusApply.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineReadyConditionType
	}); idx < 0 {
		statusApply = statusApply.WithConditions(metav1.Condition{
			Type:               MachineReadyConditionType,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: *machineApply.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             MachineReadyConditionNegReason,
			Message:            MachineReadyConditionNegMessage,
		})
	}
	if *statusApply.State == metalv1alpha1.MachineStateInitial {
		statusApply = statusApply.WithState(metalv1alpha1.MachineStateInitial)
	}
	machineApply = machineApply.WithStatus(statusApply)
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Machine{}).
		Watches(&metalv1alpha1.Inventory{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			requests := make([]reconcile.Request, 0)
			source, ok := object.(*metalv1alpha1.Inventory)
			if !ok {
				return requests
			}
			machineList := &metalv1alpha1.MachineList{}
			if err := r.List(ctx, machineList); err != nil {
				log.Error(ctx, err, "failed to list machines")
				return requests
			}
			for _, machine := range machineList.Items {
				if machine.Spec.UUID == source.Name {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      machine.GetName(),
							Namespace: machine.GetNamespace(),
						}})
					break
				}
			}
			return requests
		})).
		Complete(r)
}

// todo: move to separate package
func ConvertToApplyConfiguration(machine *metalv1alpha1.Machine) *metalv1alpha1apply.MachineApplyConfiguration {
	machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace).WithGeneration(machine.Generation)
	specApply := metalv1alpha1apply.MachineSpec()
	if machine.Spec.UUID != "" {
		specApply = specApply.WithUUID(machine.Spec.UUID)
	}
	if machine.Spec.OOBRef.Name != "" {
		specApply = specApply.WithOOBRef(machine.Spec.OOBRef)
	}
	if machine.Spec.InventoryRef != nil {
		specApply = specApply.WithInventoryRef(*machine.Spec.InventoryRef)
	}
	if machine.Spec.MachineClaimRef != nil {
		specApply = specApply.WithMachineClaimRef(*machine.Spec.MachineClaimRef)
	}
	if machine.Spec.LoopbackAddressRef != nil {
		specApply = specApply.WithLoopbackAddressRef(*machine.Spec.LoopbackAddressRef)
	}
	if machine.Spec.ASN != "" {
		specApply = specApply.WithASN(machine.Spec.ASN)
	}
	if machine.Spec.Power != "" {
		specApply = specApply.WithPower(machine.Spec.Power)
	}
	if machine.Spec.LocatorLED != "" {
		specApply = specApply.WithLocatorLED(machine.Spec.LocatorLED)
	}

	statusApply := metalv1alpha1apply.MachineStatus().
		WithConditions(machine.Status.Conditions...).
		WithState(machine.Status.State)
	return machineApply.WithSpec(specApply).WithStatus(statusApply)
}
