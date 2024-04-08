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
	"github.com/ironcore-dev/metal/internal/patch"
	"github.com/ironcore-dev/metal/internal/util"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update

const (
	MachineClaimFieldOwner     string = "metal.ironcore.dev/machineclaim"
	MachineClaimFinalizer      string = "metal.ironcore.dev/machineclaim"
	MachineClaimSpecMachineRef string = ".spec.machineRef.Name"
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

	switch {
	default:
		if claim.Spec.MachineRef == nil {
			break
		}
		ctx = log.WithValues(ctx, "machine", claim.Spec.MachineRef.Name)

		log.Debug(ctx, "Getting Machine")
		var machine metalv1alpha1.Machine
		err := r.Get(ctx, client.ObjectKey{Name: claim.Spec.MachineRef.Name}, &machine)
		if err != nil {
			if errors.IsNotFound(err) {
				break
			}
			return fmt.Errorf("cannot get Machine: %w", err)
		}
		if machine.Spec.MachineClaimRef == nil {
			break
		}
		if machine.Spec.MachineClaimRef.UID != claim.UID {
			return fmt.Errorf("MachineClaimRef in Machine does not match MachineClaim UID")
		}

		log.Debug(ctx, "Updating Machine")
		machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace).WithFinalizers().WithSpec(metalv1alpha1apply.MachineSpec())
		err = r.Patch(ctx, &machine, patch.Apply(machineApply), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
		if err != nil {
			return fmt.Errorf("cannot patch Machine: %w", err)
		}
	}

	log.Debug(ctx, "Removing finalizer")
	apply := metalv1alpha1apply.MachineClaim(claim.Name, claim.Namespace).WithFinalizers()
	err := r.Patch(ctx, claim, patch.Apply(apply), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot remove finalizer: %w", err)
	}

	log.Debug(ctx, "Finalized successfully")
	return nil
}

func (r *MachineClaimReconciler) reconcile(ctx context.Context, claim *metalv1alpha1.MachineClaim) (ctrl.Result, error) {
	log.Debug(ctx, "Reconciling")

	applySpec := metalv1alpha1apply.MachineClaimSpec()
	applyStatus := metalv1alpha1apply.MachineClaimStatus().WithPhase(metalv1alpha1.MachineClaimPhaseUnbound)

	var machines []metalv1alpha1.Machine
	if claim.Spec.MachineRef != nil {
		log.Debug(ctx, "Getting referenced Machine")
		var machine metalv1alpha1.Machine
		err := r.Get(ctx, client.ObjectKey{Name: claim.Spec.MachineRef.Name}, &machine)
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("cannot get Machine: %w", err)
		}
		if !errors.IsNotFound(err) {
			machines = append(machines, machine)
		}
	} else if claim.Spec.MachineSelector != nil {
		log.Debug(ctx, "Listing Machines with matching labels")
		var machineList metalv1alpha1.MachineList
		err := r.List(ctx, &machineList, client.MatchingLabels(claim.Spec.MachineSelector.MatchLabels))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot list Machines: %w", err)
		}
		machines = machineList.Items
	}

	for _, m := range machines {
		if m.Status.State != metalv1alpha1.MachineStateReady {
			continue
		}
		if m.Spec.MachineClaimRef != nil && m.Spec.MachineClaimRef.UID != claim.UID {
			continue
		}

		machine := m
		ctx = log.WithValues(ctx, "machine", machine.Name)

		machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace).WithFinalizers(MachineClaimFinalizer).WithSpec(metalv1alpha1apply.MachineSpec().
			WithMachineClaimRef(v1.ObjectReference{
				Namespace: claim.Namespace,
				Name:      claim.Name,
				UID:       claim.UID,
			}).
			WithPower(claim.Spec.Power))
		if !controllerutil.ContainsFinalizer(&machine, MachineClaimFinalizer) ||
			!util.NilOrEqual(machine.Spec.MachineClaimRef, machineApply.Spec.MachineClaimRef) ||
			machine.Spec.Power != *machineApply.Spec.Power {
			log.Debug(ctx, "Updating Machine")
			err := r.Patch(ctx, &machine, patch.Apply(machineApply), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("cannot patch Machine: %w", err)
			}
		}

		applySpec = applySpec.WithMachineRef(v1.LocalObjectReference{Name: machine.Name})
		applyStatus = applyStatus.WithPhase(metalv1alpha1.MachineClaimPhaseBound)

		break
	}

	apply := metalv1alpha1apply.MachineClaim(claim.Name, claim.Namespace).WithFinalizers(MachineClaimFinalizer).WithSpec(applySpec)
	if !controllerutil.ContainsFinalizer(claim, MachineClaimFinalizer) ||
		!util.NilOrEqual(claim.Spec.MachineRef, apply.Spec.MachineRef) {
		log.Debug(ctx, "Updating")
		err := r.Patch(ctx, claim, patch.Apply(apply), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim: %w", err)
		}
	}

	apply = metalv1alpha1apply.MachineClaim(claim.Name, claim.Namespace).WithStatus(applyStatus)
	if claim.Status.Phase != *apply.Status.Phase {
		log.Debug(ctx, "Updating status")
		err := r.Status().Patch(ctx, claim, patch.Apply(apply), client.FieldOwner(MachineClaimFieldOwner), client.ForceOwnership)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim status: %w", err)
		}
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
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

		claimList := &metalv1alpha1.MachineClaimList{}
		err := r.List(ctx, claimList, client.MatchingFields{MachineClaimSpecMachineRef: machine.Name})
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot list MachineClaims: %w", err))
			return nil
		}

		var req []reconcile.Request
		for _, c := range claimList.Items {
			if c.DeletionTimestamp != nil {
				continue
			}

			// TODO: Also watch for machines matching the label selector.
			req = append(req, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: c.Namespace,
				Name:      c.Name,
			}})
		}
		return req
	})
}
