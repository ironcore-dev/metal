/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/ironcore-dev/controller-utils/clientutils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
)

const (
	MachineClaimFinalizer string = "metal.ironcore.dev/machineclaim"
)

// MachineClaimReconciler reconciles a MachineClaim object
type MachineClaimReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machineclaims/finalizers,verbs=update
//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/status,verbs=get
//+kubebuilder:rbac:groups=metal.ironcore.dev,resources=machines/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO Add logs
// TODO Server-side apply
func (r *MachineClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	claim := &metalv1alpha1.MachineClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get MachineClaim: %w", err))
	}

	if !claim.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.delete(ctx, log, claim)
	}
	return r.reconcile(ctx, log, claim)
}

func (r *MachineClaimReconciler) delete(ctx context.Context, _ logr.Logger, claim *metalv1alpha1.MachineClaim) error {
	if !controllerutil.ContainsFinalizer(claim, MachineClaimFinalizer) {
		return nil
	}

	switch {
	default:
		if claim.Spec.MachineRef == nil {
			break
		}

		machine := &metalv1alpha1.Machine{}
		err := r.Get(ctx, client.ObjectKey{Name: claim.Spec.MachineRef.Name}, machine)
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

		machineBase := machine.DeepCopy()
		machine.Spec.MachineClaimRef = nil
		_ = controllerutil.RemoveFinalizer(machine, MachineClaimFinalizer)
		err = r.Patch(ctx, machine, client.MergeFrom(machineBase))
		if err != nil {
			return fmt.Errorf("cannot patch Machine: %w", err)
		}
	}

	_, err := clientutils.PatchEnsureNoFinalizer(ctx, r.Client, claim, MachineClaimFinalizer)
	if err != nil {
		return fmt.Errorf("cannot remove finalizer from MachineClaim: %w", err)
	}

	return nil
}

func (r *MachineClaimReconciler) reconcile(ctx context.Context, _ logr.Logger, claim *metalv1alpha1.MachineClaim) (ctrl.Result, error) {
	modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, claim, MachineClaimFinalizer)
	if err != nil || modified {
		return ctrl.Result{}, err
	}

	if claim.Status.Phase == "" {
		claimBase := claim.DeepCopy()
		claim.Status.Phase = metalv1alpha1.MachineClaimPhaseUnbound
		err = r.Status().Patch(ctx, claim, client.MergeFrom(claimBase))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim status: %w", err)
		}

		return ctrl.Result{}, nil
	}

	var machines []metalv1alpha1.Machine
	if claim.Spec.MachineRef == nil {
		machineList := &metalv1alpha1.MachineList{}
		err = r.List(ctx, machineList, client.MatchingLabels(claim.Spec.MachineSelector.MatchLabels))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot list Machines from MachineClaim selector: %w", err)
		}
		machines = machineList.Items
	} else {
		machine := &metalv1alpha1.Machine{}
		err = r.Get(ctx, client.ObjectKey{Name: claim.Spec.MachineRef.Name}, machine)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot get Machine from MachineClaim ref: %w", err)
		}
		machines = append(machines, *machine)
	}
	if len(machines) == 0 {
		return ctrl.Result{}, nil
	}

	var machine *metalv1alpha1.Machine
	for _, m := range machines {
		if m.Status.State != metalv1alpha1.MachineStateReady {
			continue
		}
		if m.Spec.MachineClaimRef != nil && m.Spec.MachineClaimRef.UID != claim.UID {
			continue
		}
		chosen := m
		machine = &chosen
		break
	}
	if machine == nil {
		return ctrl.Result{}, nil
	}

	machineBase := machine.DeepCopy()
	modified = controllerutil.AddFinalizer(machine, MachineClaimFinalizer)
	if machine.Spec.MachineClaimRef == nil {
		machine.Spec.MachineClaimRef = &v1.ObjectReference{
			Namespace: claim.Namespace,
			Name:      claim.Name,
			UID:       claim.UID,
		}
		modified = true
	}
	if machine.Spec.Power != claim.Spec.Power {
		machine.Spec.Power = claim.Spec.Power
		modified = true
	}
	if modified {
		err = r.Patch(ctx, machine, client.MergeFrom(machineBase))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim: %w", err)
		}
	}

	if claim.Spec.MachineRef == nil || claim.Spec.MachineRef.Name != machine.Name {
		claimBase := claim.DeepCopy()
		claim.Spec.MachineRef = &v1.LocalObjectReference{Name: machine.Name}
		err = r.Patch(ctx, claim, client.MergeFrom(claimBase))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim: %w", err)
		}
	}

	if claim.Status.Phase != metalv1alpha1.MachineClaimPhaseBound {
		claimBase := claim.DeepCopy()
		claim.Status.Phase = metalv1alpha1.MachineClaimPhaseBound
		err = r.Status().Patch(ctx, claim, client.MergeFrom(claimBase))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot patch MachineClaim status: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MachineClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// TODO: Make an index for claim.spec.machineref
	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.MachineClaim{}).
		Watches(&metalv1alpha1.Machine{}, r.enqueueMachineClaimsByRef()).
		Complete(r)
}

func (r *MachineClaimReconciler) enqueueMachineClaimsByRef() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		log := ctrl.LoggerFrom(ctx)
		machine := obj.(*metalv1alpha1.Machine)

		// TODO: Filter this list with a field selector.
		claimList := &metalv1alpha1.MachineClaimList{}
		if err := r.List(ctx, claimList); err != nil {
			log.Error(fmt.Errorf("cannot list MachineClaims: %w", err), "")
			return nil
		}

		var req []reconcile.Request
		for _, c := range claimList.Items {
			// TODO: Also watch for machines matching the label selector.
			ref := c.Spec.MachineRef
			if ref != nil && ref.Name == machine.Name {
				req = append(req, reconcile.Request{NamespacedName: types.NamespacedName{
					Namespace: c.Namespace,
					Name:      c.Name,
				}})
			}
		}
		return req
	})
}
