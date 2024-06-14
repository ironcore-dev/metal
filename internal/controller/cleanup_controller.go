package controller

import (
	"context"
	"fmt"
	"time"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const CleanupFieldManager = "metal.ironcore.dev/cleanup-controller"

func NewCleanupReconciler() (*CleanupReconciler, error) {
	return &CleanupReconciler{}, nil
}

type CleanupReconciler struct {
	client.Client
}

func (r *CleanupReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var machine metalv1alpha1.Machine
	if err := r.Get(ctx, req.NamespacedName, &machine); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Machine: %w", err))
	}
	if !machine.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	if !machine.Spec.CleanupRequired {
		return ctrl.Result{}, nil
	}

	log.Debug(ctx, "doing machine cleanup for 15 seconds")
	// todo: cleanup logic
	time.Sleep(time.Second * 15)
	machineApply := metalv1alpha1apply.Machine(machine.Name, machine.Namespace)
	machineApply = machineApply.WithSpec(metalv1alpha1apply.MachineSpec().WithCleanupRequired(false))
	return ctrl.Result{}, r.Patch(
		ctx, &machine, ssa.Apply(machineApply), client.FieldOwner(CleanupFieldManager), client.ForceOwnership)
}

func (r *CleanupReconciler) SetupWithManager(mgr manager.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Machine{}).
		Complete(r)
}
