// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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
		Watches(&metalv1alpha1.Inventory{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
			requests := make([]reconcile.Request, 0)
			inventory, ok := object.(*metalv1alpha1.Inventory)
			if !ok {
				return requests
			}
			if !inventory.DeletionTimestamp.IsZero() {
				return requests
			}

			sizeList := &metalv1alpha1.SizeList{}
			if err := r.List(ctx, sizeList); err != nil {
				log.Error(ctx, fmt.Errorf("failed to list size: %w", err))
				return requests
			}
			for _, size := range sizeList.Items {
				matches, err := size.Matches(inventory)
				if err != nil {
					log.Error(ctx, fmt.Errorf("failed to match size: %w", err))
					continue
				}
				sizeLabel := size.GetMatchLabel()
				_, labelExist := inventory.Labels[sizeLabel]
				if matches && !labelExist {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Namespace: size.Namespace,
							Name:      size.Name,
						},
					})
				}
			}
			return requests
		})).
		Complete(r)
}
