// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	ipamv1alpha1 "github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
	ipamv1alpha1apply "github.com/ironcore-dev/ipam/clientgo/applyconfiguration/ipam/v1alpha1"
	"github.com/sethvargo/go-password/password"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	v1apply "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	metalv1alpha1apply "github.com/ironcore-dev/metal/client/applyconfiguration/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/bmc"
	"github.com/ironcore-dev/metal/internal/cru"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/internal/ssa"
	"github.com/ironcore-dev/metal/internal/util"
)

// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobs/finalizers,verbs=update
// +kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips/status,verbs=get
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list

const (
	OOBFieldManager        = "metal.ironcore.dev/oob"
	OOBFinalizer           = "metal.ironcore.dev/oob"
	OOBIPMacLabel          = "mac"
	OOBIgnoreAnnotation    = "metal.ironcore.dev/oob-ignore"
	OOBMacRegex            = `^[0-9A-Fa-f]{12}$`
	OOBUsernameRegexSuffix = `[a-z]{6}`
	OOBSpecMACAddress      = ".spec.MACAddress"
	// OOBTemporaryNamespaceHack TODO: Remove temporary namespace hack.
	OOBTemporaryNamespaceHack = "oob"
)

func NewOOBReconciler(systemNamespace, ipLabelSelector, macDB, usernamePrefix, temporaryPasswordSecret string) (*OOBReconciler, error) {
	r := &OOBReconciler{
		systemNamespace:         systemNamespace,
		usernamePrefix:          usernamePrefix,
		temporaryPasswordSecret: temporaryPasswordSecret,
	}
	var err error

	if r.systemNamespace == "" {
		return nil, fmt.Errorf("system namespace cannot be empty")
	}
	if r.usernamePrefix == "" {
		return nil, fmt.Errorf("username prefix cannot be empty")
	}
	if r.temporaryPasswordSecret == "" {
		return nil, fmt.Errorf("temporary password secret name cannot be empty")
	}

	r.ipLabelSelector, err = labels.Parse(ipLabelSelector)
	if err != nil {
		return nil, fmt.Errorf("cannot parse IP label selector: %w", err)
	}

	r.macDB, err = loadMacDB(macDB)
	if err != nil {
		return nil, fmt.Errorf("cannot load MAC DB: %w", err)
	}

	r.usernameRegex, err = regexp.Compile(r.usernamePrefix + OOBUsernameRegexSuffix)
	if err != nil {
		return nil, fmt.Errorf("cannot compile username regex: %w", err)
	}

	r.macRegex, err = regexp.Compile(OOBMacRegex)
	if err != nil {
		return nil, fmt.Errorf("cannot compile MAC regex: %w", err)
	}

	return r, nil
}

// OOBReconciler reconciles a OOB object
type OOBReconciler struct {
	client.Client
	systemNamespace         string
	ipLabelSelector         labels.Selector
	macDB                   util.PrefixMap[access]
	usernamePrefix          string
	temporaryPassword       string
	temporaryPasswordSecret string
	usernameRegex           *regexp.Regexp
	macRegex                *regexp.Regexp
}

type access struct {
	Ignore             bool                   `yaml:"ignore"`
	Protocol           metalv1alpha1.Protocol `yaml:"protocol"`
	Flags              map[string]string      `yaml:"flags"`
	DefaultCredentials []bmc.Credentials      `yaml:"defaultCredentials"`
}

func (r *OOBReconciler) PreStart(ctx context.Context) error {
	return r.ensureTemporaryPassword(ctx)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *OOBReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var oob metalv1alpha1.OOB
	err := r.Get(ctx, req.NamespacedName, &oob)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get OOB: %w", err))
	}

	if !oob.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &oob)
	}
	return r.reconcile(ctx, &oob)
}

func (r *OOBReconciler) finalize(ctx context.Context, oob *metalv1alpha1.OOB) error {
	if !controllerutil.ContainsFinalizer(oob, OOBFinalizer) {
		return nil
	}
	log.Debug(ctx, "Finalizing")

	err := r.finalizeEndpoint(ctx, oob)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Removing finalizer")
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
	if err != nil {
		return err
	}
	apply.Finalizers = util.Clear(apply.Finalizers, OOBFinalizer)
	err = r.Patch(ctx, oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOB: %w", err)
	}

	log.Debug(ctx, "Finalized successfully")
	return nil
}

func (r *OOBReconciler) finalizeEndpoint(ctx context.Context, oob *metalv1alpha1.OOB) error {
	if oob.Spec.EndpointRef == nil {
		return nil
	}
	ctx = log.WithValues(ctx, "endpoint", oob.Spec.EndpointRef.Name)

	var ip ipamv1alpha1.IP
	err := r.Get(ctx, client.ObjectKey{
		Namespace: OOBTemporaryNamespaceHack,
		Name:      oob.Spec.EndpointRef.Name,
	}, &ip)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("cannot get IP: %w", err)
	}
	if errors.IsNotFound(err) {
		return nil
	}

	log.Debug(ctx, "Removing finalizer from IP")
	var ipApply *ipamv1alpha1apply.IPApplyConfiguration
	ipApply, err = ipamv1alpha1apply.ExtractIP(&ip, OOBFieldManager)
	if err != nil {
		return err
	}
	ipApply.Finalizers = util.Clear(ipApply.Finalizers, OOBFinalizer)
	ipApply.Spec = nil
	err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply IP: %w", err)
	}

	return nil
}

func (r *OOBReconciler) reconcile(ctx context.Context, oob *metalv1alpha1.OOB) (ctrl.Result, error) {
	log.Debug(ctx, "Reconciling")

	var ok bool
	var err error

	ctx, ok, err = r.applyOrContinue(log.WithValues(ctx, "phase", "IgnoreAnnotation"), oob, r.processIgnoreAnnotation)
	_, ignored := oob.Annotations[OOBIgnoreAnnotation]
	if !ok || ignored {
		if err == nil {
			log.Debug(ctx, "Reconciled successfully")
		}
		return ctrl.Result{}, err
	}

	ctx, ok, err = r.applyOrContinue(log.WithValues(ctx, "phase", "InitialState"), oob, r.processInitialState)
	if !ok {
		if err == nil {
			log.Debug(ctx, "Reconciled successfully")
		}
		return ctrl.Result{}, err
	}

	ctx, ok, err = r.applyOrContinue(log.WithValues(ctx, "phase", "Endpoint"), oob, r.processEndpoint)
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

type oobProcessFunc func(context.Context, *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error)

func (r *OOBReconciler) applyOrContinue(ctx context.Context, oob *metalv1alpha1.OOB, pfunc oobProcessFunc) (context.Context, bool, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration
	var err error

	ctx, apply, status, err = pfunc(ctx, oob)
	if err != nil {
		return ctx, false, err
	}

	if apply != nil {
		log.Debug(ctx, "Applying")
		err = r.Patch(ctx, oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, fmt.Errorf("cannot apply OOB: %w", err)
		}
	}

	if status != nil {
		apply = metalv1alpha1apply.OOB(oob.Name, oob.Namespace).WithStatus(status)

		log.Debug(ctx, "Applying status")
		err = r.Status().Patch(ctx, oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, fmt.Errorf("cannot apply OOB status: %w", err)
		}

		cond, ok := ssa.GetCondition(status.Conditions, metalv1alpha1.OOBConditionTypeReady)
		if ok && cond.Status == metav1.ConditionFalse && cond.Reason == metalv1alpha1.OOBConditionReasonError {
			err = fmt.Errorf(cond.Message)
		}
	}

	return ctx, apply == nil, err
}

func (r *OOBReconciler) processIgnoreAnnotation(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	_, ok := oob.Annotations[OOBIgnoreAnnotation]
	if ok {
		var status *metalv1alpha1apply.OOBStatusApplyConfiguration
		state := metalv1alpha1.OOBStateIgnored
		conds, mod := ssa.SetCondition(oob.Status.Conditions, metav1.Condition{
			Type:   metalv1alpha1.OOBConditionTypeReady,
			Status: metav1.ConditionFalse,
			Reason: metalv1alpha1.OOBConditionReasonIgnored,
		})
		if oob.Status.State != state || mod {
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			status = util.Ensure(applyst.Status).
				WithState(state)
			status.Conditions = conds
		}
		return ctx, nil, status, nil
	} else if oob.Status.State == metalv1alpha1.OOBStateIgnored {
		oob.Status.State = ""
	}

	return ctx, nil, nil, nil
}

func (r *OOBReconciler) processInitialState(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration
	var err error

	ctx = log.WithValues(ctx, "mac", oob.Spec.MACAddress)

	if !controllerutil.ContainsFinalizer(oob, OOBFinalizer) {
		apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		apply.Finalizers = util.Set(apply.Finalizers, OOBFinalizer)
	}

	_, ok := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if oob.Status.State == "" || !ok {
		var applyst *metalv1alpha1apply.OOBApplyConfiguration
		applyst, err = metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		status = util.Ensure(applyst.Status).
			WithState(metalv1alpha1.OOBStateUnready)
		status.Conditions, _ = ssa.SetCondition(oob.Status.Conditions, metav1.Condition{
			Type:   metalv1alpha1.OOBConditionTypeReady,
			Status: metav1.ConditionFalse,
			Reason: metalv1alpha1.OOBConditionReasonInProgress,
		})
	}

	return ctx, apply, status, nil
}

func (r *OOBReconciler) processEndpoint(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration

	var ip ipamv1alpha1.IP
	if oob.Spec.EndpointRef != nil {
		err := r.Get(ctx, client.ObjectKey{
			Namespace: OOBTemporaryNamespaceHack,
			Name:      oob.Spec.EndpointRef.Name,
		}, &ip)
		if err != nil && !errors.IsNotFound(err) {
			return ctx, nil, nil, fmt.Errorf("cannot get IP: %w", err)
		}

		valid := ip.DeletionTimestamp == nil && r.ipLabelSelector.Matches(labels.Set(ip.Labels)) && ip.Namespace == OOBTemporaryNamespaceHack
		if errors.IsNotFound(err) || !valid {
			if !valid && controllerutil.ContainsFinalizer(&ip, OOBFinalizer) {
				log.Debug(ctx, "Removing finalizer from IP")
				var ipApply *ipamv1alpha1apply.IPApplyConfiguration
				ipApply, err = ipamv1alpha1apply.ExtractIP(&ip, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
				ipApply.Finalizers = util.Clear(ipApply.Finalizers, OOBFinalizer)
				err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
				if err != nil {
					return ctx, nil, nil, fmt.Errorf("cannot apply IP: %w", err)
				}
			}

			oob.Spec.EndpointRef = nil

			apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec))
			apply.Spec.EndpointRef = nil
		} else if ip.Status.Reserved != nil {
			ctx = log.WithValues(ctx, "ip", ip.Status.Reserved.String())
		}
	}
	if oob.Spec.EndpointRef == nil {
		var ipList ipamv1alpha1.IPList
		err := r.List(ctx, &ipList, client.MatchingLabelsSelector{Selector: r.ipLabelSelector}, client.MatchingLabels{OOBIPMacLabel: oob.Spec.MACAddress})
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot list OOBs: %w", err)
		}

		found := false
		for _, i := range ipList.Items {
			if i.Namespace != OOBTemporaryNamespaceHack {
				continue
			}
			if i.DeletionTimestamp != nil || i.Status.State != ipamv1alpha1.CFinishedIPState || i.Status.Reserved == nil || !i.Status.Reserved.Net.IsValid() {
				continue
			}
			ip = i
			found = true
			ctx = log.WithValues(ctx, "ip", ip.Status.Reserved.String())

			oob.Spec.EndpointRef = &v1.LocalObjectReference{
				Name: ip.Name,
			}

			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithEndpointRef(*oob.Spec.EndpointRef))

			state := metalv1alpha1.OOBStateUnready
			conds, mod := ssa.SetCondition(oob.Status.Conditions, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
			if oob.Status.State != state || mod {
				var applyst *metalv1alpha1apply.OOBApplyConfiguration
				applyst, err = metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
				status = util.Ensure(applyst.Status).
					WithState(state)
				status.Conditions = conds
			}

			break
		}
		if !found {
			state := metalv1alpha1.OOBStateUnready
			conds, mod := ssa.SetCondition(oob.Status.Conditions, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonNoEndpoint,
			})
			if oob.Status.State != state || mod {
				var applyst *metalv1alpha1apply.OOBApplyConfiguration
				applyst, err = metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, err
				}
				status = util.Ensure(applyst.Status).
					WithState(state)
				status.Conditions = conds
			}
			return ctx, apply, status, nil
		}
	}

	if !controllerutil.ContainsFinalizer(&ip, OOBFinalizer) {
		log.Debug(ctx, "Adding finalizer to IP")
		ipApply, err := ipamv1alpha1apply.ExtractIP(&ip, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, err
		}
		ipApply.Finalizers = util.Set(ipApply.Finalizers, OOBFinalizer)
		err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot apply IP: %w", err)
		}
	}

	if ip.Labels[OOBIPMacLabel] != oob.Spec.MACAddress {
		state := metalv1alpha1.OOBStateError
		conds, mod := ssa.SetErrorCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady,
			fmt.Errorf("BadEndpoint: endpoint has incorrect MAC address: expected %s, actual %s", oob.Spec.MACAddress, ip.Labels[OOBIPMacLabel]))
		if oob.Status.State != state || mod {
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			status = util.Ensure(applyst.Status).
				WithState(state)
			status.Conditions = conds
		}
		return ctx, apply, status, nil
	}

	if ip.Status.State != ipamv1alpha1.CFinishedIPState || ip.Status.Reserved == nil || !ip.Status.Reserved.Net.IsValid() {
		state := metalv1alpha1.OOBStateError
		conds, mod := ssa.SetErrorCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady,
			fmt.Errorf("BadEndpoint: endpoint has no valid IP address"))
		if oob.Status.State != state || mod {
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			status = util.Ensure(applyst.Status).
				WithState(state)
			status.Conditions = conds
		}
		return ctx, apply, status, nil
	}

	if oob.Status.State == metalv1alpha1.OOBStateError {
		cond, _ := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
		if strings.HasPrefix(cond.Message, "BadEndpoint: ") {
			state := metalv1alpha1.OOBStateUnready
			conds, _ := ssa.SetCondition(oob.Status.Conditions, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, err
			}
			status = util.Ensure(applyst.Status).
				WithState(state)
			status.Conditions = conds

			return ctx, apply, status, nil
		}
	}

	return ctx, apply, status, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OOBReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	c, err := cru.CreateController(mgr, &metalv1alpha1.OOB{}, r)
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &ipamv1alpha1.IP{}), r.enqueueOOBFromIP())
	if err != nil {
		return err
	}

	return mgr.Add(c)
}

func (r *OOBReconciler) enqueueOOBFromIP() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		ip := obj.(*ipamv1alpha1.IP)

		if ip.Namespace != OOBTemporaryNamespaceHack {
			return nil
		}
		if !r.ipLabelSelector.Matches(labels.Set(ip.Labels)) {
			return nil
		}

		mac, ok := ip.Labels[OOBIPMacLabel]
		if !ok || !r.macRegex.MatchString(mac) {
			log.Error(ctx, fmt.Errorf("invalid MAC address: %s", mac))
			return nil
		}

		oobList := metalv1alpha1.OOBList{}
		err := r.List(ctx, &oobList, client.MatchingFields{OOBSpecMACAddress: mac})
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot list OOBs: %w", err))
			return nil
		}

		var reqs []reconcile.Request
		for _, o := range oobList.Items {
			if o.DeletionTimestamp != nil {
				continue
			}

			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Name: o.Name,
			}})
		}

		if len(oobList.Items) == 0 && ip.Status.State == ipamv1alpha1.CFinishedIPState && ip.Status.Reserved != nil {
			oob := metalv1alpha1.OOB{
				ObjectMeta: metav1.ObjectMeta{
					Name: mac,
				},
			}
			apply := metalv1alpha1apply.OOB(oob.Name, oob.Namespace).
				WithFinalizers(OOBFinalizer).
				WithSpec(metalv1alpha1apply.OOBSpec().
					WithMACAddress(mac))
			err = r.Patch(ctx, &oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
			if err != nil {
				log.Error(ctx, fmt.Errorf("cannot apply OOB: %w", err))
			}
		}

		return reqs
	})
}

func loadMacDB(dbFile string) (util.PrefixMap[access], error) {
	if dbFile == "" {
		return make(util.PrefixMap[access]), nil
	}

	data, err := os.ReadFile(dbFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dbFile, err)
	}

	var dbf struct {
		MACs []struct {
			Prefix string `yaml:"prefix"`
			access `yaml:",inline"`
		} `yaml:"macs"`
	}
	err = yaml.Unmarshal(data, &dbf)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal %s: %w", dbFile, err)
	}

	db := make(util.PrefixMap[access], len(dbf.MACs))
	for _, m := range dbf.MACs {
		db[m.Prefix] = m.access
	}
	return db, nil
}

func (r *OOBReconciler) ensureTemporaryPassword(ctx context.Context) error {
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.temporaryPasswordSecret,
			Namespace: r.systemNamespace,
		},
	}

	err := r.Get(ctx, client.ObjectKeyFromObject(&secret), &secret)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("cannot get secret %s: %w", r.temporaryPasswordSecret, err)
	}
	ctx = log.WithValues(ctx, "name", secret.Name, "namesapce", secret.Namespace)

	if errors.IsNotFound(err) {
		var pw string
		pw, err = password.Generate(12, 0, 0, false, true)
		if err != nil {
			return fmt.Errorf("cannot generate temporary password: %w", err)
		}

		log.Info(ctx, "Creating new temporary password Secret")
		apply := v1apply.Secret(secret.Name, secret.Namespace).
			WithType(v1.SecretTypeBasicAuth).
			WithStringData(map[string]string{v1.BasicAuthPasswordKey: pw})
		err = r.Patch(ctx, &secret, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return fmt.Errorf("cannot apply Secret: %w", err)
		}
	} else {
		log.Info(ctx, "Loading existing temporary password Secret")
	}

	if secret.Type != v1.SecretTypeBasicAuth {
		return fmt.Errorf("cannot use Secret with incorrect type: %s", secret.Type)
	}

	r.temporaryPassword = string(secret.Data[v1.BasicAuthPasswordKey])
	if r.temporaryPassword == "" {
		return fmt.Errorf("cannot use Secret with missing or empty password")
	}

	return nil
}
