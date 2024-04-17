// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	"github.com/ironcore-dev/metal/internal/util"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update

const (
	MachineClaimFieldManager   = "metal.ironcore.dev/machineclaim"
	MachineClaimFinalizer      = "metal.ironcore.dev/machineclaim"
	MachineClaimSpecMachineRef = ".spec.machineRef.Name"
)

func NewMachineClaimReconciler() (*MachineClaimReconciler, error) {
	return &MachineClaimReconciler{}, nil
}

// MachineClaimReconciler reconciles a MachineClaim object
type MachineClaimReconciler struct {
	client.Client
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MachineClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var claim metalv1alpha1.MachineClaim
	err := r.Get(ctx, req.NamespacedName, &claim)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get MachineClaim: %w", err))
	}

	if !claim.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &claim)
	}
	return r.reconcile(ctx, &claim)
}

func (r *MachineClaimReconciler) finalize(ctx context.Context, claim *metalv1alpha1.MachineClaim) error {
	if !controllerutil.ContainsFinalizer(claim, MachineClaimFinalizer) {
		return nil
	}
	log.Debug(ctx, "Finalizing")

	err := r.finalizeMachine(ctx, claim)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Removing finalizer")
	var apply *metalv1alpha1apply.MachineClaimApplyConfiguration
	apply, err = metalv1alpha1apply.ExtractMachineClaim(claim, MachineClaimFieldManager)
	if err != nil {
		return err
	}
	apply.Finalizers = util.Clear(apply.Finalizers, MachineClaimFinalizer)
	err = r.Patch(ctx, claim, ssa.Apply(apply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply MachineClaim: %w", err)
	}

	log.Debug(ctx, "Finalized successfully")
	return nil
}

func (r *MachineClaimReconciler) finalizeMachine(ctx context.Context, claim *metalv1alpha1.MachineClaim) error {
	if claim.Spec.MachineRef == nil {
		return nil
	}
	ctx = log.WithValues(ctx, "machine", claim.Spec.MachineRef.Name)

	var machine metalv1alpha1.Machine
	err := r.Get(ctx, client.ObjectKey{
		Name: claim.Spec.MachineRef.Name,
	}, &machine)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("cannot get Machine: %w", err)
	}
	if errors.IsNotFound(err) {
		return nil
	}

	if machine.Spec.MachineClaimRef == nil {
		return nil
	}
	if machine.Spec.MachineClaimRef.UID != claim.UID {
		return fmt.Errorf("MachineClaimRef in Machine does not match MachineClaim UID")
	}

	log.Debug(ctx, "Removing finalizer from Machine and clearing MachineClaimRef and Power")
	var machineApply *metalv1alpha1apply.MachineApplyConfiguration
	machineApply, err = metalv1alpha1apply.ExtractMachine(&machine, MachineClaimFieldManager)
	if err != nil {
		return err
	}
	machineApply.Finalizers = util.Clear(machineApply.Finalizers, MachineClaimFinalizer)
	machineApply.Spec = nil
	err = r.Patch(ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply Machine: %w", err)
	}

	return nil
}

func (r *MachineClaimReconciler) reconcile(ctx context.Context, claim *metalv1alpha1.MachineClaim) (ctrl.Result, error) {
	log.Debug(ctx, "Reconciling")

	var ok bool
	var err error

	ctx, ok, err = r.applyOrContinue(log.WithValues(ctx, "phase", "InitialState"), claim, r.processInitialState)
	if !ok {
		if err == nil {
			log.Debug(ctx, "Reconciled successfully")
		}
		return ctrl.Result{}, err
	}

	ctx, ok, err = r.applyOrContinue(log.WithValues(ctx, "phase", "Machine"), claim, r.processMachine)
	if !ok {
		if err == nil {
			log.Debug(ctx, "Reconciled successfully")
		}
		return ctrl.Result{}, err
	}

	ctx = log.WithValues(ctx, "phase", "all")
	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
}

type nachineClaimProcessFunc func(context.Context, *metalv1alpha1.MachineClaim) (context.Context, *metalv1alpha1apply.MachineClaimApplyConfiguration, *metalv1alpha1apply.MachineClaimStatusApplyConfiguration, error)

func (r *MachineClaimReconciler) applyOrContinue(ctx context.Context, claim *metalv1alpha1.MachineClaim, pfunc nachineClaimProcessFunc) (context.Context, bool, error) {
	var apply *metalv1alpha1apply.MachineClaimApplyConfiguration
	var status *metalv1alpha1apply.MachineClaimStatusApplyConfiguration
	var err error

	ctx, apply, status, err = pfunc(ctx, claim)
	if err != nil {
		return ctx, false, err
	}

	if apply != nil {
		log.Debug(ctx, "Applying")
		err = r.Patch(ctx, claim, ssa.Apply(apply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, fmt.Errorf("cannot apply MachineClaim: %w", err)
		}
	}

	if status != nil {
		apply = metalv1alpha1apply.MachineClaim(claim.Name, claim.Namespace).WithStatus(status)

		log.Debug(ctx, "Applying status")
		err = r.Status().Patch(ctx, claim, ssa.Apply(apply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, fmt.Errorf("cannot apply MachineClaim status: %w", err)
		}
	}

	return ctx, apply == nil, err
}

func (r *MachineClaimReconciler) processInitialState(ctx context.Context, claim *metalv1alpha1.MachineClaim) (context.Context, *metalv1alpha1apply.MachineClaimApplyConfiguration, *metalv1alpha1apply.MachineClaimStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.MachineClaimApplyConfiguration
	var status *metalv1alpha1apply.MachineClaimStatusApplyConfiguration
	var err error

	if !controllerutil.ContainsFinalizer(claim, MachineClaimFinalizer) {
		apply, err = metalv1alpha1apply.ExtractMachineClaim(claim, MachineClaimFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		apply.Finalizers = util.Set(apply.Finalizers, MachineClaimFinalizer)
	}

	if claim.Status.Phase == "" {
		var applyst *metalv1alpha1apply.MachineClaimApplyConfiguration
		applyst, err = metalv1alpha1apply.ExtractMachineClaimStatus(claim, MachineClaimFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		status = util.Ensure(applyst.Status).
			WithPhase(metalv1alpha1.MachineClaimPhaseUnbound)
	}

	return ctx, apply, status, nil
}

func (r *MachineClaimReconciler) processMachine(ctx context.Context, claim *metalv1alpha1.MachineClaim) (context.Context, *metalv1alpha1apply.MachineClaimApplyConfiguration, *metalv1alpha1apply.MachineClaimStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.MachineClaimApplyConfiguration
	var status *metalv1alpha1apply.MachineClaimStatusApplyConfiguration
	var err error

	var machine metalv1alpha1.Machine
	if claim.Spec.MachineRef != nil {
		err = r.Get(ctx, client.ObjectKey{
			Name: claim.Spec.MachineRef.Name,
		}, &machine)
		if err != nil && !errors.IsNotFound(err) {
			return ctx, nil, nil, fmt.Errorf("cannot get Machine: %w", err)
		}

		if errors.IsNotFound(err) {
			claim.Spec.MachineRef = nil

			apply, err = metalv1alpha1apply.ExtractMachineClaim(claim, MachineClaimFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec))
			apply.Spec.MachineRef = nil
		}
	}
	if claim.Spec.MachineRef == nil {
		var machineList metalv1alpha1.MachineList
		if claim.Spec.MachineSelector != nil {
			err = r.List(ctx, &machineList, client.MatchingLabels(claim.Spec.MachineSelector.MatchLabels))
			if err != nil {
				return ctx, nil, nil, fmt.Errorf("cannot list Machines: %w", err)
			}
		}

		found := false
		for _, m := range machineList.Items {
			if m.DeletionTimestamp != nil || m.Status.State != metalv1alpha1.MachineStateReady || (m.Spec.MachineClaimRef != nil && m.Spec.MachineClaimRef.UID != claim.UID) {
				continue
			}
			machine = m
			found = true
			ctx = log.WithValues(ctx, "machine", machine.Name)

			claim.Spec.MachineRef = &v1.LocalObjectReference{
				Name: machine.Name,
			}

			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractMachineClaim(claim, MachineClaimFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithMachineRef(*claim.Spec.MachineRef))

			break
		}
		if !found {
			phase := metalv1alpha1.MachineClaimPhaseUnbound
			if claim.Status.Phase != phase {
				var applyst *metalv1alpha1apply.MachineClaimApplyConfiguration
				applyst, err = metalv1alpha1apply.ExtractMachineClaimStatus(claim, MachineClaimFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
				status = util.Ensure(applyst.Status).
					WithPhase(phase)
			}

			return ctx, apply, status, nil
		}
	}

	claimRef := v1.ObjectReference{
		Namespace: claim.Namespace,
		Name:      claim.Name,
		UID:       claim.UID,
	}

	if machine.Status.State != metalv1alpha1.MachineStateReady {
		log.Debug(ctx, "Removing finalizer from Machine and clearing MachineClaimRef and Power")
		var machineApply *metalv1alpha1apply.MachineApplyConfiguration
		machineApply, err = metalv1alpha1apply.ExtractMachine(&machine, MachineClaimFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		machineApply.Finalizers = util.Clear(machineApply.Finalizers, MachineClaimFinalizer)
		machineApply = nil
		err = r.Patch(ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot apply Machine: %w", err)
		}

		phase := metalv1alpha1.MachineClaimPhaseUnbound
		if claim.Status.Phase != phase {
			var applyst *metalv1alpha1apply.MachineClaimApplyConfiguration
			applyst, err = metalv1alpha1apply.ExtractMachineClaimStatus(claim, MachineClaimFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			status = util.Ensure(applyst.Status).
				WithPhase(phase)
		}

		return ctx, apply, status, nil
	}

	if !controllerutil.ContainsFinalizer(&machine, MachineClaimFinalizer) ||
		!util.NilOrEqual(machine.Spec.MachineClaimRef, &claimRef) ||
		machine.Spec.Power != claim.Spec.Power {
		log.Debug(ctx, "Adding finalizer to Machine and setting MachineClaimRef and Power")
		var machineApply *metalv1alpha1apply.MachineApplyConfiguration
		machineApply, err = metalv1alpha1apply.ExtractMachine(&machine, MachineClaimFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		machineApply.Finalizers = util.Set(machineApply.Finalizers, MachineClaimFinalizer)
		machineApply = machineApply.WithSpec(util.Ensure(machineApply.Spec).
			WithMachineClaimRef(claimRef).
			WithPower(claim.Spec.Power))
		err = r.Patch(ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(MachineClaimFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot apply Machine: %w", err)
		}
	}

	phase := metalv1alpha1.MachineClaimPhaseBound
	if claim.Status.Phase != phase {
		var applyst *metalv1alpha1apply.MachineClaimApplyConfiguration
		applyst, err = metalv1alpha1apply.ExtractMachineClaimStatus(claim, MachineClaimFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		status = util.Ensure(applyst.Status).
			WithPhase(phase)
	}

	return ctx, apply, status, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.MachineClaim{}).
		Watches(&metalv1alpha1.Machine{}, r.enqueueMachineClaimsFromMachine()).
		Complete(r)
}

func (r *MachineClaimReconciler) enqueueMachineClaimsFromMachine() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		machine := obj.(*metalv1alpha1.Machine)

		claimList := metalv1alpha1.MachineClaimList{}
		err := r.List(ctx, &claimList, client.MatchingFields{MachineClaimSpecMachineRef: machine.Name})
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot list MachineClaims: %w", err))
			return nil
		}

		var reqs []reconcile.Request
		for _, c := range claimList.Items {
			if c.DeletionTimestamp != nil {
				continue
			}

			// TODO: Also watch for machines matching the label selector.
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: c.Namespace,
				Name:      c.Name,
			}})
		}
		return reqs
	})
}
