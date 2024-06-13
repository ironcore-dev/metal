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

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=aggregates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=aggregates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=aggregates/finalizers,verbs=update
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories,verbs=get;list;watch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=inventories/status,verbs=get;update;patch

const (
	AggregateFinalizer  = "aggregate.metal.ironcore.dev/finalizer"
	AggregateFieldOwner = "metal.ironcore.dev/aggregate"
)

func NewAggregateReconciler() (*AggregateReconciler, error) {
	return &AggregateReconciler{}, nil
}

type AggregateReconciler struct {
	client.Client
}

func (r *AggregateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var aggregate metalv1alpha1.Aggregate
	if err := r.Get(ctx, req.NamespacedName, &aggregate); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Aggregate: %w", err))
	}
	if !aggregate.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&aggregate, AggregateFinalizer) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.finalize(ctx, &aggregate)
	}

	return ctrl.Result{}, r.reconcile(ctx, &aggregate)
}

func (r *AggregateReconciler) reconcile(ctx context.Context, aggregate *metalv1alpha1.Aggregate) error {
	if !controllerutil.ContainsFinalizer(aggregate, AggregateFinalizer) {
		aggregateApply := metalv1alpha1apply.Aggregate(aggregate.Name, aggregate.Namespace).
			WithFinalizers(AggregateFinalizer)
		return r.Patch(
			ctx, aggregate, ssa.Apply(aggregateApply), client.FieldOwner(AggregateFieldOwner), client.ForceOwnership)
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
		aggregatedValues, err := aggregate.Compute(&inventory)
		if err != nil {
			log.Error(ctx, fmt.Errorf("failed to compute aggregated values: %w", err), "inventory", inventory.Name)
			continue
		}
		inventoryApply := metalv1alpha1apply.Inventory(inventory.Name, inventory.Namespace)
		inventoryStatusApply := metalv1alpha1apply.InventoryStatus()
		aggregateResults := inventory.Status.Computed.Object
		if aggregateResults == nil {
			aggregateResults = make(map[string]interface{})
		}
		aggregateResults[aggregate.Name] = aggregatedValues
		inventoryStatusApply = inventoryStatusApply.
			WithComputed(metalv1alpha1.AggregationResults{Object: aggregateResults})
		inventoryApply = inventoryApply.WithStatus(inventoryStatusApply)
		if err := r.Status().Patch(
			ctx, &inventory, ssa.Apply(inventoryApply), client.FieldOwner(AggregateFieldOwner), client.ForceOwnership); err != nil {
			log.Error(ctx, fmt.Errorf("failed to patch inventory: %w", err), "inventory", inventory.Name)
		}
	}

	return nil
}

func (r *AggregateReconciler) finalize(ctx context.Context, aggregate *metalv1alpha1.Aggregate) error {
	inventories := &metalv1alpha1.InventoryList{}
	if err := r.List(ctx, inventories); err != nil {
		log.Error(ctx, fmt.Errorf("failed to list inventories: %w", err))
		return err
	}
	for _, inventory := range inventories.Items {
		computed := inventory.Status.Computed.Object
		_, ok := computed[aggregate.Name]
		if !ok {
			continue
		}
		delete(computed, aggregate.Name)
		inventoryApply := metalv1alpha1apply.Inventory(inventory.Name, inventory.Namespace)
		inventoryStatusApply := metalv1alpha1apply.InventoryStatus()
		inventoryStatusApply = inventoryStatusApply.
			WithComputed(metalv1alpha1.AggregationResults{Object: computed})
		inventoryApply = inventoryApply.WithStatus(inventoryStatusApply)
		if err := r.Status().Patch(
			ctx, &inventory, ssa.Apply(inventoryApply), client.FieldOwner(AggregateFieldOwner), client.ForceOwnership); err != nil {
			log.Error(ctx, fmt.Errorf("failed to patch inventory: %w", err), "inventory", inventory.Name)
		}
	}

	aggregateApply := metalv1alpha1apply.Aggregate(aggregate.Name, aggregate.Namespace).
		WithFinalizers()
	return r.Patch(ctx, aggregate, ssa.Apply(aggregateApply), client.FieldOwner(AggregateFieldOwner), client.ForceOwnership)
}

func (r *AggregateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Aggregate{}).
		Complete(r)
}
