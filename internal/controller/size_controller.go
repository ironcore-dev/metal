package controller

import (
	"context"
	"fmt"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	SizeFinalizer  = "size.metal.ironcore.dev/finalizer"
	SizeFieldOwner = "metal.ironcore.dev/size"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=sizes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=sizes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=sizes/finalizers,verbs=update

func NewSizeReconciler() (*SizeReconciler, error) {
	return &SizeReconciler{}, nil
}

type SizeReconciler struct {
	client.Client
}

func (r *SizeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var size metalv1alpha1.Size
	if err := r.Get(ctx, req.NamespacedName, &size); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Size: %w", err))
	}
	if !size.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&size, SizeFinalizer) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.finalize(ctx, size)
	}

	return ctrl.Result{}, r.reconcile(ctx, size)
}

func (r *SizeReconciler) reconcile(ctx context.Context, size metalv1alpha1.Size) error {
	if !controllerutil.ContainsFinalizer(&size, SizeFinalizer) {
		sizeApply := metalv1alpha1apply.Size(size.Name, size.Namespace).
			WithFinalizers(SizeFinalizer)
		return r.Patch(ctx, &size, ssa.Apply(sizeApply), client.FieldOwner(SizeFieldOwner), client.ForceOwnership)
	}

	inventories := &metalv1alpha1.InventoryList{}
	if err := r.List(ctx, inventories); err != nil {
		log.Error(ctx, fmt.Errorf("failed to list inventories: %w", err))
		return err
	}

	for _, inventory := range inventories.Items {
		if !inventory.DeletionTimestamp.IsZero() {
			continue
		}

		var labels map[string]string
		if inventory.Labels == nil {
			labels = make(map[string]string)
		} else {
			labels = inventory.Labels
		}

		matches, err := size.Matches(&inventory)
		if err != nil {
			log.Error(ctx, fmt.Errorf("failed to match size: %w", err))
		}
		sizeLabel := size.GetMatchLabel()
		_, labelPresent := labels[sizeLabel]

		switch matches {
		case true:
			if labelPresent {
				log.Debug(ctx, "match between inventory and size found, label present, will not update")
				continue
			} else {
				log.Info(ctx, "match between inventory and size found")
				labels[sizeLabel] = "true"
			}
		case false:
			if labelPresent {
				log.Info(ctx, "inventory no longer matches to size, will remove label")
				delete(labels, sizeLabel)
			} else {
				log.Debug(ctx, "match between inventory and size is not found, label absent, will not update")
				continue
			}
		}

		inventoryApply := metalv1alpha1apply.Inventory(inventory.Name, inventory.Namespace).
			WithLabels(labels)
		err = r.Patch(
			ctx, &inventory, ssa.Apply(inventoryApply), client.FieldOwner(SizeFieldOwner), client.ForceOwnership)
		if err != nil {
			log.Error(ctx, fmt.Errorf("failed to patch inventory: %w", err))
		}
	}

	return nil
}

func (r *SizeReconciler) finalize(ctx context.Context, size metalv1alpha1.Size) error {
	inventories := &metalv1alpha1.InventoryList{}
	if err := r.List(ctx, inventories); err != nil {
		log.Error(ctx, fmt.Errorf("failed to list inventories: %w", err))
		return err
	}

	sizeLabel := size.GetMatchLabel()
	for _, inventory := range inventories.Items {
		var labels map[string]string
		if inventory.Labels == nil {
			labels = make(map[string]string)
		} else {
			labels = inventory.Labels
		}

		if _, labelPresent := labels[sizeLabel]; !labelPresent {
			continue
		}

		delete(labels, sizeLabel)
		inventoryApply := metalv1alpha1apply.Inventory(inventory.Name, inventory.Namespace).
			WithLabels(labels)
		err := r.Patch(
			ctx, &inventory, ssa.Apply(inventoryApply), client.FieldOwner(SizeFieldOwner), client.ForceOwnership)
		if err != nil {
			log.Error(ctx, fmt.Errorf("failed to patch inventory: %w", err))
		}
	}

	sizeApply := metalv1alpha1apply.Size(size.Name, size.Namespace).
		WithFinalizers()
	return r.Patch(ctx, &size, ssa.Apply(sizeApply), client.FieldOwner(SizeFieldOwner), client.ForceOwnership)
}

func (r *SizeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Size{}).
		Complete(r)
}
