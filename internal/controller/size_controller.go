package controller

import (
	"context"
	"fmt"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
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

	return ctrl.Result{}, nil
}

func (r *SizeReconciler) finalize(ctx context.Context, size metalv1alpha1.Size) error {
	return nil
}

func (r *SizeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	return ctrl.NewControllerManagedBy(mgr).
		For(&metalv1alpha1.Size{}).
		Complete(r)
}
