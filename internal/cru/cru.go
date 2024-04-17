// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package cru

import (
	"context"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type preStartReconciler interface {
	reconcile.Reconciler
	PreStart(context.Context) error
}

type preStartController struct {
	controller.Controller
	preStart func(context.Context) error
}

func (c *preStartController) Start(ctx context.Context) error {
	err := c.preStart(ctx)
	if err != nil {
		return err
	}

	return c.Controller.Start(ctx)
}

func CreateController(mgr ctrl.Manager, obj client.Object, reconciler reconcile.Reconciler) (controller.Controller, error) {
	gvk, err := apiutil.GVKForObject(obj, mgr.GetScheme())
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(gvk.Kind)
	cl := mgr.GetLogger().WithValues("controller", name, "controllerGroup", gvk.Group, "controllerKind", gvk.Kind)

	var c controller.Controller
	c, err = controller.NewUnmanaged(name, mgr, controller.Options{
		MaxConcurrentReconciles: mgr.GetControllerOptions().GroupKindConcurrency[gvk.GroupKind().String()],
		Reconciler:              reconciler,
		LogConstructor: func(req *reconcile.Request) logr.Logger {
			rl := cl
			if req != nil {
				rl = rl.WithValues(gvk.Kind, klog.KRef(req.Namespace, req.Name), "namespace", req.Namespace, "name", req.Name)
			}
			return rl
		},
	})
	if err != nil {
		return nil, err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), obj), &handler.EnqueueRequestForObject{})
	if err != nil {
		return nil, err
	}

	psr, ok := reconciler.(preStartReconciler)
	if ok {
		return &preStartController{
			Controller: c,
			preStart:   psr.PreStart,
		}, nil
	}

	return c, nil
}

func InClusterNamespace() string {
	ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return ""
	}
	return string(ns)
}
