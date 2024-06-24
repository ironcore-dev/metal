// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories,verbs=get;list;watch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories/status,verbs=get
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=bootconfigurations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=bootconfigurations/status,verbs=get

const (
	MachineFieldManager    string = "metal.ironcore.dev/machine"
	MachineFinalizer       string = "machine.metal.ironcore.dev/finalizer"
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

func NewMachineReconciler(machineInventoryBootImage, systemNamespace string) (*MachineReconciler, error) {
	if machineInventoryBootImage == "" {
		return nil, fmt.Errorf("no machine inventory boot image provided")
	}
	return &MachineReconciler{
		machineInventoryBootImage: machineInventoryBootImage,
		systemNamespace:           systemNamespace,
	}, nil
}

// MachineReconciler reconciles a Machine object
type MachineReconciler struct {
	client.Client

	machineInventoryBootImage string
	systemNamespace           string
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

	machineApply, err := r.reconcile(ctx, &machine)
	if machineApply.Spec != nil {
		machineApply.Status = nil
		return ctrl.Result{}, r.Patch(
			ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineFieldManager), client.ForceOwnership)
	}
	if machineApply.Status != nil {
		machineApply.Spec = nil
		return ctrl.Result{}, r.Status().Patch(
			ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineFieldManager), client.ForceOwnership)
	}
	return ctrl.Result{}, err
}

func (r *MachineReconciler) reconcile(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
) (*metalv1alpha1apply.MachineApplyConfiguration, error) {
	var machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration
	machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace)

	switch {
	case machine.Spec.Maintenance:
		machineStatusApply = metalv1alpha1apply.MachineStatus().WithState(metalv1alpha1.MachineStateMaintenance)
		r.fillConditions(machine, machineStatusApply)
	case machine.Spec.InventoryRef == nil && machine.Status.State == metalv1alpha1.MachineStateInitial &&
		conditionTrue(machine.Status.Conditions, MachineInitializedConditionType):
		machineSpecApply, err := r.evaluateInitialBoot(ctx, machine)
		if err != nil {
			return machineApply, err
		}
		if machineSpecApply == nil {
			return machineApply, nil
		}
		return machineApply.WithSpec(machineSpecApply), nil
	default:
		machineStatusApply = metalv1alpha1apply.MachineStatus()
		r.fillConditions(machine, machineStatusApply)
		r.evaluateConditions(ctx, machine, machineStatusApply)
		r.evaluateCleanupRequired(machine, machineStatusApply)
		r.evaluateReadiness(machine, machineStatusApply)
		r.evaluateAvailability(ctx, machine, machineStatusApply)
		r.evaluateErrorState(machine, machineStatusApply)
	}
	if machineStatusApply != nil {
		machineApply = machineApply.WithStatus(machineStatusApply)
	}
	return machineApply, nil
}

func (r *MachineReconciler) evaluateInitialBoot(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
) (*metalv1alpha1apply.MachineSpecApplyConfiguration, error) {
	if machine.Spec.Power == metalv1alpha1.PowerOn {
		return nil, nil
	}
	if machine.Spec.BootConfigurationRef == nil || machine.Spec.BootConfigurationRef.Name == "" {
		if err := r.createBootConfiguration(ctx, machine); err != nil {
			log.Error(ctx, fmt.Errorf("failed to create boot configuration: %w", err))
			return nil, err
		}
		machineSpecApply := metalv1alpha1apply.MachineSpec()
		return machineSpecApply.
			WithBootConfigurationRef(corev1.LocalObjectReference{Name: machine.Name}), nil
	}

	bootConfig := &metalv1alpha1.BootConfiguration{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: "",
		Name:      machine.Spec.BootConfigurationRef.Name,
	}, bootConfig); err != nil {
		log.Error(ctx, fmt.Errorf("failed to get boot configuration: %w", err))
		return nil, err
	}
	if bootConfig.Status.State != metalv1alpha1.BootConfigurationStateReady {
		return nil, nil
	}
	log.Info(ctx, "Boot configuration is ready")
	machineSpecApply := metalv1alpha1apply.MachineSpec()
	return machineSpecApply.
		WithPower(metalv1alpha1.PowerOn).
		WithBootConfigurationRef(corev1.LocalObjectReference{Name: machine.Name}), nil
}

func (r *MachineReconciler) evaluateConditions(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	r.initialize(ctx, machine, machineStatusApply)
	r.inventorize(ctx, machine, machineStatusApply)
	r.classify(machine, machineStatusApply)
}

func (r *MachineReconciler) evaluateCleanupRequired(
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	r.sanitize(machine, machineStatusApply)
	if machine.Spec.CleanupRequired {
		machineStatusApply.State = ptr.To(metalv1alpha1.MachineStateTainted)
	}
}

func (r *MachineReconciler) initialize(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	var oob metalv1alpha1.OOB
	idx := slices.IndexFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineInitializedConditionType
	})
	baseCondition := machineStatusApply.Conditions[idx]
	condition := v1.Condition().
		WithType(*baseCondition.Type).
		WithLastTransitionTime(*baseCondition.LastTransitionTime).
		WithObservedGeneration(*baseCondition.ObservedGeneration)
	statusTransition := false

	key := types.NamespacedName{Name: machine.Spec.OOBRef.Name}
	err := r.Get(ctx, key, &oob)
	switch {
	case err != nil:
		log.Error(ctx, fmt.Errorf("failed to get oob: %w", err))
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineInitializedConditionNegReason).
			WithMessage(fmt.Sprintf("Cannot get OOB object: %v", err))
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	case conditionTrue(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady):
		condition = condition.
			WithStatus(metav1.ConditionTrue).
			WithReason(MachineInitializedConditionPosReason).
			WithMessage(MachineInitializedConditionPosMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionFalse
	default:
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineInitializedConditionNegReason).
			WithMessage(MachineInitializedConditionNegMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		condition = condition.
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
	}
	machineStatusApply.Conditions[idx] = *condition
	machineStatusApply.State = ptr.To(metalv1alpha1.MachineStateInitial)
}

func (r *MachineReconciler) inventorize(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	var inventory metalv1alpha1.Inventory
	idx := slices.IndexFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineInventoriedConditionType
	})
	baseCondition := machineStatusApply.Conditions[idx]
	condition := v1.Condition().
		WithType(*baseCondition.Type).
		WithLastTransitionTime(*baseCondition.LastTransitionTime).
		WithObservedGeneration(*baseCondition.ObservedGeneration)
	statusTransition := false

	if machine.Spec.InventoryRef == nil {
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineInventoriedConditionNegReason).
			WithMessage(MachineInventoriedConditionNegMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	} else {
		key := types.NamespacedName{Name: machine.Spec.InventoryRef.Name}
		err := r.Get(ctx, key, &inventory)
		switch {
		case err != nil:
			log.Error(ctx, fmt.Errorf("failed to get inventory: %w", err))
			condition = condition.
				WithStatus(metav1.ConditionFalse).
				WithReason(MachineInventoriedConditionNegReason).
				WithMessage(fmt.Sprintf("Cannot get Inventory object: %v", err))
			statusTransition = *baseCondition.Status == metav1.ConditionTrue
		default:
			networkInterfacesToApply := make([]*metalv1alpha1apply.MachineNetworkInterfaceApplyConfiguration, 0)
			for _, nic := range inventory.Spec.NICs {
				nicApply := metalv1alpha1apply.MachineNetworkInterface().
					WithName(nic.Name).
					WithMacAddress(convertMacAddress(nic.MACAddress))
				networkInterfacesToApply = append(networkInterfacesToApply, nicApply)
			}
			machineStatusApply = machineStatusApply.WithNetworkInterfaces(networkInterfacesToApply...)

			condition = condition.
				WithStatus(metav1.ConditionTrue).
				WithReason(MachineInventoriedConditionPosReason).
				WithMessage(MachineInventoriedConditionPosMessage)
			statusTransition = *baseCondition.Status == metav1.ConditionFalse
		}
	}
	if statusTransition {
		condition = condition.
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
	}
	machineStatusApply.Conditions[idx] = *condition
}

func (r *MachineReconciler) classify(
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	// note: size label should be set by size controller
	idx := slices.IndexFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineClassifiedConditionType
	})
	baseCondition := machineStatusApply.Conditions[idx]
	condition := v1.Condition().
		WithType(*baseCondition.Type).
		WithLastTransitionTime(*baseCondition.LastTransitionTime).
		WithObservedGeneration(*baseCondition.ObservedGeneration)
	statusTransition := false
	notClassified := true

	for lbl := range machine.GetLabels() {
		if !strings.HasPrefix(lbl, MachineSizeLabelPrefix) {
			continue
		}
		condition = condition.
			WithStatus(metav1.ConditionTrue).
			WithReason(MachineClassifiedConditionPosReason).
			WithMessage(MachineClassifiedConditionPosMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionFalse
		notClassified = false
		break
	}
	if notClassified {
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineClassifiedConditionNegReason).
			WithMessage(MachineClassifiedConditionNegMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		condition = condition.
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
	}
	machineStatusApply.Conditions[idx] = *condition
}

func (r *MachineReconciler) sanitize(
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	idx := slices.IndexFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineSanitizedConditionType
	})
	baseCondition := machineStatusApply.Conditions[idx]
	condition := v1.Condition().
		WithType(*baseCondition.Type).
		WithLastTransitionTime(*baseCondition.LastTransitionTime).
		WithObservedGeneration(*baseCondition.ObservedGeneration)
	statusTransition := false

	if machine.Spec.CleanupRequired {
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineSanitizedConditionNegReason).
			WithMessage(MachineSanitizedConditionNegMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	} else {
		condition = condition.
			WithStatus(metav1.ConditionTrue).
			WithReason(MachineSanitizedConditionPosReason).
			WithMessage(MachineSanitizedConditionPosMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionFalse
	}
	if statusTransition {
		condition = condition.
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
	}
	machineStatusApply.Conditions[idx] = *condition
}

func (r *MachineReconciler) evaluateReadiness(
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	idx := slices.IndexFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineReadyConditionType
	})
	baseCondition := machineStatusApply.Conditions[idx]
	condition := v1.Condition().
		WithType(*baseCondition.Type).
		WithLastTransitionTime(*baseCondition.LastTransitionTime).
		WithObservedGeneration(*baseCondition.ObservedGeneration)
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
		condition = condition.
			WithStatus(metav1.ConditionTrue).
			WithReason(MachineReadyConditionPosReason).
			WithMessage(MachineReadyConditionPosMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionFalse
	} else {
		condition = condition.
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineReadyConditionNegReason).
			WithMessage(MachineReadyConditionNegMessage)
		statusTransition = *baseCondition.Status == metav1.ConditionTrue
	}
	if statusTransition {
		condition = condition.
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
	}
	machineStatusApply.Conditions[idx] = *condition
}

func (r *MachineReconciler) evaluateAvailability(
	ctx context.Context,
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	if machine.Spec.MachineClaimRef != nil && machine.Spec.MachineClaimRef.Name != "" {
		machineStatusApply.State = ptr.To(metalv1alpha1.MachineStateReserved)
		return
	}

	if !slices.ContainsFunc(machineStatusApply.Conditions, func(c v1.ConditionApplyConfiguration) bool {
		return *c.Type == MachineReadyConditionType && *c.Status == metav1.ConditionTrue
	}) {
		return
	}

	if machine.Status.Power == metalv1alpha1.PowerOff {
		if err := r.deleteBootConfiguration(ctx, machine); err != nil {
			log.Error(ctx, err)
			return
		}
		machineStatusApply.State = ptr.To(metalv1alpha1.MachineStateAvailable)
	} else {
		machineStatusApply.State = ptr.To(machine.Status.State)
	}
}

// nolint: staticcheck
func (r *MachineReconciler) fillConditions(machine *metalv1alpha1.Machine, machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration) {
	conditionsToApply := make([]v1.ConditionApplyConfiguration, 0)
	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInitializedConditionType
	}); idx < 0 {
		condition := v1.Condition().
			WithType(MachineInitializedConditionType).
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineInitializedConditionNegReason).
			WithMessage(MachineInitializedConditionNegMessage).
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
		conditionsToApply = append(conditionsToApply, *condition)
	} else {
		c := machine.Status.Conditions[idx]
		condition := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsToApply = append(conditionsToApply, *condition)
	}

	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineInventoriedConditionType
	}); idx < 0 {
		condition := v1.Condition().
			WithType(MachineInventoriedConditionType).
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineInventoriedConditionNegReason).
			WithMessage(MachineInventoriedConditionNegMessage).
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
		conditionsToApply = append(conditionsToApply, *condition)
	} else {
		c := machine.Status.Conditions[idx]
		condition := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsToApply = append(conditionsToApply, *condition)
	}

	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineClassifiedConditionType
	}); idx < 0 {
		condition := v1.Condition().
			WithType(MachineClassifiedConditionType).
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineClassifiedConditionNegReason).
			WithMessage(MachineClassifiedConditionNegMessage).
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
		conditionsToApply = append(conditionsToApply, *condition)
	} else {
		c := machine.Status.Conditions[idx]
		condition := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsToApply = append(conditionsToApply, *condition)
	}

	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineSanitizedConditionType
	}); idx < 0 {
		condition := v1.Condition().
			WithType(MachineSanitizedConditionType).
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineSanitizedConditionNegReason).
			WithMessage(MachineSanitizedConditionNegMessage).
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
		conditionsToApply = append(conditionsToApply, *condition)
	} else {
		c := machine.Status.Conditions[idx]
		condition := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsToApply = append(conditionsToApply, *condition)
	}

	if idx := slices.IndexFunc(machine.Status.Conditions, func(condition metav1.Condition) bool {
		return condition.Type == MachineReadyConditionType
	}); idx < 0 {
		condition := v1.Condition().
			WithType(MachineReadyConditionType).
			WithStatus(metav1.ConditionFalse).
			WithReason(MachineReadyConditionNegReason).
			WithMessage(MachineReadyConditionNegMessage).
			WithLastTransitionTime(metav1.Now()).
			WithObservedGeneration(machine.Generation)
		conditionsToApply = append(conditionsToApply, *condition)
	} else {
		c := machine.Status.Conditions[idx]
		condition := v1.Condition().
			WithType(c.Type).
			WithStatus(c.Status).
			WithReason(c.Reason).
			WithMessage(c.Message).
			WithLastTransitionTime(c.LastTransitionTime).
			WithObservedGeneration(c.ObservedGeneration)
		conditionsToApply = append(conditionsToApply, *condition)
	}
	machineStatusApply.Conditions = conditionsToApply
}

func (r *MachineReconciler) evaluateErrorState(
	machine *metalv1alpha1.Machine,
	machineStatusApply *metalv1alpha1apply.MachineStatusApplyConfiguration,
) {
	// todo: error flag might be changed. For now it will be annotation
	_, ok := machine.Annotations[MachineErrorAnnotation]
	if !ok {
		return
	}
	// todo: clarify whether this check is needed or not. Workflow without this check will be the following:
	//  If reserved machine will get into error state, then machine claim controller will cleanup spec.machineClaimRef.
	//  Therefore, machine controller will not set Reserved state back, after error is resolved.
	if machine.Spec.MachineClaimRef == nil || machine.Spec.MachineClaimRef.Name == "" {
		machineStatusApply.State = ptr.To(metalv1alpha1.MachineStateError)
	}
}

func (r *MachineReconciler) createBootConfiguration(ctx context.Context, machine *metalv1alpha1.Machine) error {
	log.Info(ctx, "Creating boot configuration")
	bootConfig := &metalv1alpha1.BootConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: machine.Name,
		},
		Spec: metalv1alpha1.BootConfigurationSpec{
			MachineRef:        &corev1.LocalObjectReference{Name: machine.Name},
			IgnitionSecretRef: &corev1.ObjectReference{Name: machine.Name, Namespace: r.systemNamespace},
			Image:             r.machineInventoryBootImage,
		},
	}
	if err := ctrl.SetControllerReference(machine, bootConfig, r.Scheme()); err != nil {
		return err
	}
	existing := metav1.GetControllerOf(bootConfig)
	owner := metav1apply.OwnerReference().
		WithAPIVersion(existing.APIVersion).
		WithKind(existing.Kind).
		WithName(existing.Name).
		WithUID(existing.UID).
		WithController(*existing.Controller).
		WithBlockOwnerDeletion(*existing.BlockOwnerDeletion)
	bootConfigApply := metalv1alpha1apply.BootConfiguration(bootConfig.Name, "").
		WithOwnerReferences(owner)
	bootConfigSpecApply := metalv1alpha1apply.BootConfigurationSpec().
		WithImage(r.machineInventoryBootImage).
		WithMachineRef(corev1.LocalObjectReference{Name: machine.Name}).
		WithIgnitionSecretRef(corev1.ObjectReference{Name: machine.Name, Namespace: r.systemNamespace})
	bootConfigApply = bootConfigApply.WithSpec(bootConfigSpecApply)
	return r.Patch(
		ctx, bootConfig, ssa.Apply(bootConfigApply), client.FieldOwner(MachineFieldManager), client.ForceOwnership)
}

func (r *MachineReconciler) deleteBootConfiguration(ctx context.Context, machine *metalv1alpha1.Machine) error {
	log.Info(ctx, "Deleting boot configuration")
	bootConfiguration := &metalv1alpha1.BootConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: machine.Name,
		}}
	return client.IgnoreNotFound(r.Delete(ctx, bootConfiguration))
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Machine{}).
		Watches(&metalv1alpha1.Inventory{}, handler.EnqueueRequestForOwner(
			mgr.GetScheme(), mgr.GetRESTMapper(), &metalv1alpha1.Machine{}, handler.OnlyControllerOwner())).
		Watches(&metalv1alpha1.BootConfiguration{}, handler.EnqueueRequestForOwner(
			mgr.GetScheme(), mgr.GetRESTMapper(), &metalv1alpha1.Machine{}, handler.OnlyControllerOwner())).
		Watches(&metalv1alpha1.OOB{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			requests := make([]reconcile.Request, 0)
			source, ok := object.(*metalv1alpha1.OOB)
			if !ok {
				return requests
			}
			machineList := &metalv1alpha1.MachineList{}
			if err := r.List(ctx, machineList); err != nil {
				log.Error(ctx, err, "failed to list machines")
				return requests
			}
			for _, machine := range machineList.Items {
				if machine.Spec.OOBRef.Name == source.Name {
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

func conditionTrue(conditions []metav1.Condition, typ string) bool {
	idx := slices.IndexFunc(conditions, func(c metav1.Condition) bool {
		return c.Type == typ && c.Status == metav1.ConditionTrue
	})
	return idx >= 0
}

func convertMacAddress(src string) string {
	var mac = src
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return mac
}
