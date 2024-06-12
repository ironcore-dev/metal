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
	"github.com/ironcore-dev/metal/internal/factory"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories,verbs=get;list;watch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories/status,verbs=get

const (
	MachineFieldOwner      string = "metal.ironcore.dev/machine"
	MachineFinalizer       string = "metal.ironcore.dev/machine"
	MachineErrorAnnotation string = "metal.ironcore.dev/error"
	MachineSizeLabelPrefix string = "metal.ironcore.dev/size-"

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

	MachineSanitizedConditionType       = "Sanitized"
	MachineSanitizedConditionPosReason  = "MachineSanitized"
	MachineSanitizedConditionNegReason  = "MachineNotSanitized"
	MachineSanitizedConditionNegMessage = "Machine not sanitized"
	MachineSanitizedConditionPosMessage = "Machine sanitized"

	MachineReadyConditionType       = "Ready"
	MachineReadyConditionPosReason  = "MachineReady"
	MachineReadyConditionNegReason  = "MachineNotReady"
	MachineReadyConditionNegMessage = "Machine not ready"
	MachineReadyConditionPosMessage = "Machine ready"

	MachineSpecOOBRefName = ".spec.oobRef.Name"
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
		ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineFieldOwner), client.ForceOwnership)
}

func (r *MachineReconciler) reconcile(ctx context.Context, machine *metalv1alpha1.Machine) *metalv1alpha1apply.MachineApplyConfiguration {
	r.fillConditions(machine)
	if machine.Spec.Maintenance {
		machine.Status.State = metalv1alpha1.MachineStateMaintenance
	} else {
		r.evaluateConditions(ctx, machine)
		r.evaluateCleanupRequired(machine)
		r.evaluateReadiness(machine)
		r.evaluateAvailability(machine)
	}
	r.evaluateErrorState(machine)
	return convertToApplyConfiguration(machine)
}

func (r *MachineReconciler) evaluateConditions(ctx context.Context, machine *metalv1alpha1.Machine) {
	r.initialize(ctx, machine)
	r.inventorize(ctx, machine)
	r.classify(machine)
}

func (r *MachineReconciler) evaluateCleanupRequired(machine *metalv1alpha1.Machine) {
	r.sanitize(machine)
	if machine.Spec.CleanupRequired {
		machine.Status.State = metalv1alpha1.MachineStateTainted
	}
}

func (r *MachineReconciler) initialize(ctx context.Context, machine *metalv1alpha1.Machine) {
	var oob metalv1alpha1.OOB
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineInitializedConditionType
	})
	baseCondition := machine.Status.Conditions[idx]
	conditionBuilder := factory.NewConditionBuilder(baseCondition.DeepCopy())
	statusTransition := false

	key := types.NamespacedName{Name: machine.Spec.OOBRef.Name}
	err := r.Get(ctx, key, &oob)
	switch {
	case err != nil:
		log.Error(ctx, err, "failed to get oob object")
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineInitializedConditionNegReason)).
			AddProperty(factory.ConditionMessage(fmt.Sprintf("Cannot get OOB object: %v", err)))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	case oob.Status.Manufacturer != "" && oob.Status.SerialNumber != "":
		machine.Status.Manufacturer = oob.Status.Manufacturer
		machine.Status.SerialNumber = oob.Status.SerialNumber
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionTrue)).
			AddProperty(factory.ConditionReason(MachineInitializedConditionPosReason)).
			AddProperty(factory.ConditionMessage(MachineInitializedConditionPosMessage))
		statusTransition = baseCondition.Status == metav1.ConditionFalse
	default:
		machine.Status.Manufacturer = ""
		machine.Status.SerialNumber = ""
		machine.Status.SKU = ""
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineInitializedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineInitializedConditionNegMessage))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ObservedGeneration(machine.Generation))
	}
	machine.Status.Conditions[idx] = *conditionBuilder.Build()
	machine.Status.State = metalv1alpha1.MachineStateInitial
}

func (r *MachineReconciler) inventorize(ctx context.Context, machine *metalv1alpha1.Machine) {
	var inventory metalv1alpha1.Inventory
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineInventoriedConditionType
	})
	baseCondition := machine.Status.Conditions[idx]
	conditionBuilder := factory.NewConditionBuilder(baseCondition.DeepCopy())
	statusTransition := false

	if machine.Spec.InventoryRef == nil {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineInventoriedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineInventoriedConditionNegMessage))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	} else {
		key := types.NamespacedName{Name: machine.Spec.InventoryRef.Name}
		err := r.Get(ctx, key, &inventory)
		switch {
		case err != nil:
			log.Error(ctx, err, "failed to get inventory object")
			conditionBuilder = conditionBuilder.
				AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
				AddProperty(factory.ConditionReason(MachineInventoriedConditionNegReason)).
				AddProperty(factory.ConditionMessage(fmt.Sprintf("Cannot get Inventory object: %v", err)))
			statusTransition = baseCondition.Status == metav1.ConditionTrue
		default:
			networkInterfaces := make([]metalv1alpha1.MachineNetworkInterface, 0, len(inventory.Spec.NICs))
			for _, nic := range inventory.Spec.NICs {
				networkInterfaces = append(networkInterfaces, metalv1alpha1.MachineNetworkInterface{
					Name:       nic.Name,
					MacAddress: convertMacAddress(nic.MACAddress),
				})
			}
			machine.Status.NetworkInterfaces = networkInterfaces
			conditionBuilder = conditionBuilder.
				AddProperty(factory.ConditionStatus(metav1.ConditionTrue)).
				AddProperty(factory.ConditionReason(MachineInventoriedConditionPosReason)).
				AddProperty(factory.ConditionMessage(MachineInventoriedConditionPosMessage))
			statusTransition = baseCondition.Status == metav1.ConditionFalse
		}
	}
	if statusTransition {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ObservedGeneration(machine.Generation))
	}
	machine.Status.Conditions[idx] = *conditionBuilder.Build()
}

func (r *MachineReconciler) classify(machine *metalv1alpha1.Machine) {
	// note: size label should be set by size controller
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineClassifiedConditionType
	})
	baseCondition := machine.Status.Conditions[idx]
	conditionBuilder := factory.NewConditionBuilder(baseCondition.DeepCopy())
	statusTransition := false
	notClassified := true

	for lbl := range machine.GetLabels() {
		if !strings.HasPrefix(lbl, MachineSizeLabelPrefix) {
			continue
		}
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionTrue)).
			AddProperty(factory.ConditionReason(MachineClassifiedConditionPosReason)).
			AddProperty(factory.ConditionMessage(MachineClassifiedConditionPosMessage))
		statusTransition = baseCondition.Status == metav1.ConditionFalse
		notClassified = false
		break
	}
	if notClassified {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineClassifiedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineClassifiedConditionNegMessage))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ObservedGeneration(machine.Generation))
	}
	machine.Status.Conditions[idx] = *conditionBuilder.Build()
}

func (r *MachineReconciler) sanitize(machine *metalv1alpha1.Machine) {
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineSanitizedConditionType
	})
	baseCondition := machine.Status.Conditions[idx]
	conditionBuilder := factory.NewConditionBuilder(baseCondition.DeepCopy())
	statusTransition := false

	if machine.Spec.CleanupRequired {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineSanitizedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineSanitizedConditionNegMessage))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	} else {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionTrue)).
			AddProperty(factory.ConditionReason(MachineSanitizedConditionPosReason)).
			AddProperty(factory.ConditionMessage(MachineSanitizedConditionPosMessage))
		statusTransition = baseCondition.Status == metav1.ConditionFalse
	}
	if statusTransition {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ObservedGeneration(machine.Generation))
	}
	machine.Status.Conditions[idx] = *conditionBuilder.Build()
}

func (r *MachineReconciler) evaluateReadiness(machine *metalv1alpha1.Machine) {
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineReadyConditionType
	})
	baseCondition := machine.Status.Conditions[idx]
	conditionBuilder := factory.NewConditionBuilder(baseCondition.DeepCopy())
	statusTransition := false

	initialized := slices.ContainsFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInitializedConditionType && condition.Status == metav1.ConditionTrue
	})
	inventoried := slices.ContainsFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType && condition.Status == metav1.ConditionTrue
	})
	classified := slices.ContainsFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineClassifiedConditionType && condition.Status == metav1.ConditionTrue
	})
	sanitized := slices.ContainsFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineSanitizedConditionType && condition.Status == metav1.ConditionTrue
	})

	if initialized && inventoried && classified && sanitized {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionTrue)).
			AddProperty(factory.ConditionReason(MachineReadyConditionPosReason)).
			AddProperty(factory.ConditionMessage(MachineReadyConditionPosMessage))
		statusTransition = baseCondition.Status == metav1.ConditionFalse
	} else {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ConditionReason(MachineReadyConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineReadyConditionNegMessage))
		statusTransition = baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		conditionBuilder = conditionBuilder.
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ObservedGeneration(machine.Generation))
	}
	machine.Status.Conditions[idx] = *conditionBuilder.Build()
}

func (r *MachineReconciler) evaluateAvailability(machine *metalv1alpha1.Machine) {
	idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
		return c.Type == MachineReadyConditionType
	})
	if machine.Status.Conditions[idx].Status == metav1.ConditionFalse {
		return
	}

	if machine.Spec.MachineClaimRef != nil && machine.Spec.MachineClaimRef.Name != "" {
		machine.Status.State = metalv1alpha1.MachineStateReserved
	} else {
		machine.Status.State = metalv1alpha1.MachineStateAvailable
	}
}

func (r *MachineReconciler) fillConditions(machine *metalv1alpha1.Machine) {
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInitializedConditionType
	}); idx < 0 {
		conditionBuilder := factory.NewConditionBuilder(&metav1.Condition{})
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionType(MachineInitializedConditionType)).
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ObservedGeneration(machine.Generation)).
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ConditionReason(MachineInitializedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineInitializedConditionNegMessage))
		machine.Status.Conditions = append(machine.Status.Conditions, *conditionBuilder.Build())
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType
	}); idx < 0 {
		conditionBuilder := factory.NewConditionBuilder(&metav1.Condition{})
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionType(MachineInventoriedConditionType)).
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ObservedGeneration(machine.Generation)).
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ConditionReason(MachineInventoriedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineInventoriedConditionNegMessage))
		machine.Status.Conditions = append(machine.Status.Conditions, *conditionBuilder.Build())
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineClassifiedConditionType
	}); idx < 0 {
		conditionBuilder := factory.NewConditionBuilder(&metav1.Condition{})
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionType(MachineClassifiedConditionType)).
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ObservedGeneration(machine.Generation)).
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ConditionReason(MachineClassifiedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineClassifiedConditionNegMessage))
		machine.Status.Conditions = append(machine.Status.Conditions, *conditionBuilder.Build())
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineSanitizedConditionType
	}); idx < 0 {
		conditionBuilder := factory.NewConditionBuilder(&metav1.Condition{})
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionType(MachineSanitizedConditionType)).
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ObservedGeneration(machine.Generation)).
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ConditionReason(MachineSanitizedConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineSanitizedConditionNegMessage))
		machine.Status.Conditions = append(machine.Status.Conditions, *conditionBuilder.Build())
	}
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineReadyConditionType
	}); idx < 0 {
		conditionBuilder := factory.NewConditionBuilder(&metav1.Condition{})
		conditionBuilder = conditionBuilder.
			AddProperty(factory.ConditionType(MachineReadyConditionType)).
			AddProperty(factory.ConditionStatus(metav1.ConditionFalse)).
			AddProperty(factory.ObservedGeneration(machine.Generation)).
			AddProperty(factory.LastTransitionTime(metav1.Now())).
			AddProperty(factory.ConditionReason(MachineReadyConditionNegReason)).
			AddProperty(factory.ConditionMessage(MachineReadyConditionNegMessage))
		machine.Status.Conditions = append(machine.Status.Conditions, *conditionBuilder.Build())
	}
}

func (r *MachineReconciler) evaluateErrorState(machine *metalv1alpha1.Machine) {
	// todo: error flag might be changed. For now it will be annotation
	_, ok := machine.Annotations[MachineErrorAnnotation]
	if !ok {
		return
	}
	// todo: clarify whether this check is needed or not. Workflow without this check will be the following:
	//  If reserved machine will get into error state, then machine claim controller will cleanup spec.machineClaimRef.
	//  Therefore, machine controller will not set Reserved state back, after error is resolved.
	if machine.Spec.MachineClaimRef == nil || machine.Spec.MachineClaimRef.Name == "" {
		machine.Status.State = metalv1alpha1.MachineStateError
	}
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
							Name: machine.GetName(),
						}})
					break
				}
			}
			return requests
		})).
		Complete(r)
}

func convertToApplyConfiguration(machine *metalv1alpha1.Machine) *metalv1alpha1apply.MachineApplyConfiguration {
	machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace).
		WithGeneration(machine.Generation).
		WithLabels(machine.Labels).
		WithAnnotations(machine.Annotations)

	specApply := metalv1alpha1apply.MachineSpec().
		WithUUID(machine.Spec.UUID).
		WithOOBRef(machine.Spec.OOBRef).
		WithASN(machine.Spec.ASN).
		WithCleanupRequired(machine.Spec.CleanupRequired).
		WithMaintenance(machine.Spec.Maintenance)
	if machine.Spec.LocatorLED != "" {
		specApply = specApply.WithLocatorLED(machine.Spec.LocatorLED)
	}
	if machine.Spec.Power != "" {
		specApply = specApply.WithPower(machine.Spec.Power)
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

	nicApplyList := make([]*metalv1alpha1apply.MachineNetworkInterfaceApplyConfiguration, 0, len(machine.Status.NetworkInterfaces))
	for _, nic := range machine.Status.NetworkInterfaces {
		nicApply := metalv1alpha1apply.MachineNetworkInterface().
			WithName(nic.Name).
			WithMacAddress(nic.MacAddress)
		if nic.IPRef != nil {
			nicApply = nicApply.WithIPRef(*nic.IPRef)
		}
		if nic.SwitchRef != nil {
			nicApply = nicApply.WithSwitchRef(*nic.SwitchRef)
		}
		nicApplyList = append(nicApplyList, nicApply)
	}

	conditionsApply := make([]*v1.ConditionApplyConfiguration, 0, len(machine.Status.Conditions))
	for _, c := range machine.Status.Conditions {
		conditionApply := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsApply = append(conditionsApply, conditionApply)
	}
	statusApply := metalv1alpha1apply.MachineStatus().
		WithSKU(machine.Status.SKU).
		WithSerialNumber(machine.Status.SerialNumber).
		WithManufacturer(machine.Status.Manufacturer).
		WithConditions(conditionsApply...).
		WithState(machine.Status.State).
		WithNetworkInterfaces(nicApplyList...)
	if machine.Status.LocatorLED != "" {
		statusApply = statusApply.WithLocatorLED(machine.Status.LocatorLED)
	}
	if machine.Status.Power != "" {
		statusApply = statusApply.WithPower(machine.Status.Power)
	}
	if machine.Status.ShutdownDeadline != nil {
		statusApply = statusApply.WithShutdownDeadline(*machine.Status.ShutdownDeadline)
	}

	return machineApply.WithSpec(specApply).WithStatus(statusApply)
}

func convertMacAddress(src string) string {
	var mac = src
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return mac
}
