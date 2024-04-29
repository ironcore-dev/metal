// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

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
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobsecrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips/status,verbs=get
// +kubebuilder:rbac:groups=metal.ironcore.dev,resources=oobs/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch

const (
	OOBFieldManager         = "metal.ironcore.dev/oob"
	OOBFinalizer            = "metal.ironcore.dev/oob"
	OOBIPMacLabel           = "mac"
	OOBIgnoreAnnotation     = "metal.ironcore.dev/oob-ignore"
	OOBMacRegex             = `^[0-9A-Fa-f]{12}$`
	OOBUsernameRegexSuffix  = `[a-z]{6}`
	OOBSpecMACAddress       = ".spec.MACAddress"
	OOBSecretSpecMACAddress = ".spec.MACAddress"
	// OOBTemporaryNamespaceHack TODO: Remove temporary namespace hack.
	OOBTemporaryNamespaceHack = "oob"

	OOBErrorBadEndpoint    = "BadEndpoint"
	OOBErrorBadCredentials = "BadCredentials"
)

func NewOOBReconciler(systemNamespace, ipLabelSelector, macDB string, credsRenewalBeforeExpiry time.Duration, usernamePrefix, temporaryPasswordSecret string) (*OOBReconciler, error) {
	r := &OOBReconciler{
		systemNamespace:              systemNamespace,
		credsRenewalTimeBeforeExpiry: credsRenewalBeforeExpiry,
		usernamePrefix:               usernamePrefix,
		temporaryPasswordSecret:      temporaryPasswordSecret,
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
	systemNamespace              string
	ipLabelSelector              labels.Selector
	macDB                        util.PrefixMap[access]
	credsRenewalTimeBeforeExpiry time.Duration
	usernamePrefix               string
	temporaryPassword            string
	temporaryPasswordSecret      string
	usernameRegex                *regexp.Regexp
	macRegex                     *regexp.Regexp
}

type access struct {
	Ignore             bool                   `yaml:"ignore"`
	Protocol           metalv1alpha1.Protocol `yaml:"protocol"`
	Flags              map[string]string      `yaml:"flags"`
	DefaultCredentials []bmc.Credentials      `yaml:"defaultCredentials"`
}

type ctxkOOBHost struct{}

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

	err = r.finalizeSecret(ctx, oob)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Removing finalizer")
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
	if err != nil {
		return fmt.Errorf("cannot extract OOB: %w", err)
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
		return fmt.Errorf("cannot extract IP: %w", err)
	}
	ipApply.Finalizers = util.Clear(ipApply.Finalizers, OOBFinalizer)
	ipApply.Spec = nil
	err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply IP: %w", err)
	}

	return nil
}

func (r *OOBReconciler) finalizeSecret(ctx context.Context, oob *metalv1alpha1.OOB) error {
	if oob.Spec.SecretRef == nil {
		return nil
	}
	ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

	var secret metalv1alpha1.OOBSecret
	err := r.Get(ctx, client.ObjectKey{
		Name: oob.Spec.SecretRef.Name,
	}, &secret)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("cannot get OOBSecret: %w", err)
	}
	if errors.IsNotFound(err) {
		return nil
	}

	log.Debug(ctx, "Removing finalizer from OOBSecret")
	var secretApply *metalv1alpha1apply.OOBSecretApplyConfiguration
	secretApply, err = metalv1alpha1apply.ExtractOOBSecret(&secret, OOBFieldManager)
	if err != nil {
		return fmt.Errorf("cannot extract OOBSecret: %w", err)
	}
	secretApply.Finalizers = util.Clear(secretApply.Finalizers, OOBFinalizer)
	err = r.Patch(ctx, &secret, ssa.Apply(secretApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOBSecret: %w", err)
	}

	return nil
}

func (r *OOBReconciler) reconcile(ctx context.Context, oob *metalv1alpha1.OOB) (ctrl.Result, error) {
	log.Debug(ctx, "Reconciling")

	var advance bool
	var err error

	ctx, advance, err = r.runPhase(ctx, oob, oobRecPhase{
		name:         "IgnoreAnnotation",
		run:          r.processIgnoreAnnotation,
		readyReasons: []string{metalv1alpha1.OOBConditionReasonIgnored},
	})
	if !advance {
		return ctrl.Result{}, err
	}

	ctx, advance, err = r.runPhase(ctx, oob, oobRecPhase{
		name: "Initial",
		run:  r.processInitial,
	})
	if !advance {
		return ctrl.Result{}, err
	}

	ctx, advance, err = r.runPhase(ctx, oob, oobRecPhase{
		name:         "Endpoint",
		run:          r.processEndpoint,
		errType:      OOBErrorBadEndpoint,
		readyReasons: []string{metalv1alpha1.OOBConditionReasonNoEndpoint},
	})
	if !advance {
		return ctrl.Result{}, err
	}

	ctx, advance, err = r.runPhase(ctx, oob, oobRecPhase{
		name:    "Credentials",
		run:     r.processCredentials,
		errType: OOBErrorBadCredentials,
	})
	if !advance {
		return ctrl.Result{}, err
	}

	ctx, advance, err = r.runPhase(ctx, oob, oobRecPhase{
		name:         "Ready",
		run:          r.processReady,
		readyReasons: []string{metalv1alpha1.OOBConditionReasonReady},
	})
	if !advance {
		return ctrl.Result{}, err
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
}

type oobRecPhase struct {
	name         string
	run          func(context.Context, *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error)
	errType      string
	readyReasons []string
}

func (r *OOBReconciler) runPhase(ctx context.Context, oob *metalv1alpha1.OOB, phase oobRecPhase) (context.Context, bool, error) {
	ctx = log.WithValues(ctx, "phase", phase.name)
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration
	var err error

	if phase.run == nil {
		return ctx, true, nil
	}

	ctx, apply, status, err = phase.run(ctx, oob)
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
	}

	cond, ok := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if ok {
		if cond.Reason == metalv1alpha1.OOBConditionReasonError && strings.HasPrefix(cond.Message, phase.errType+": ") {
			return ctx, false, fmt.Errorf(cond.Message)
		}
		if slices.Contains(phase.readyReasons, cond.Reason) {
			log.Debug(ctx, "Reconciled successfully")
			return ctx, false, nil
		}
	}

	advance := apply == nil
	if !advance {
		log.Debug(ctx, "Reconciled successfully")
	}
	return ctx, advance, nil
}

func (r *OOBReconciler) setCondition(ctx context.Context, oob *metalv1alpha1.OOB, apply *metalv1alpha1apply.OOBApplyConfiguration, status *metalv1alpha1apply.OOBStatusApplyConfiguration, state metalv1alpha1.OOBState, cond metav1.Condition) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	conds, mod := ssa.SetCondition(oob.Status.Conditions, cond)
	if oob.Status.State != state || mod {
		if status == nil {
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, fmt.Errorf("cannot extract OOB status: %w", err)
			}
			status = util.Ensure(applyst.Status)
		}
		status = status.WithState(state)
		status.Conditions = conds
	}
	return ctx, apply, status, nil
}

func (r *OOBReconciler) setError(ctx context.Context, oob *metalv1alpha1.OOB, apply *metalv1alpha1apply.OOBApplyConfiguration, status *metalv1alpha1apply.OOBStatusApplyConfiguration, errType string, err error) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	if errType != "" {
		err = fmt.Errorf("%s: %w", errType, err)
	}

	return r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateError, metav1.Condition{
		Type:    metalv1alpha1.OOBConditionTypeReady,
		Status:  metav1.ConditionFalse,
		Reason:  metalv1alpha1.OOBConditionReasonError,
		Message: err.Error(),
	})
}

func (r *OOBReconciler) processIgnoreAnnotation(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	_, ok := oob.Annotations[OOBIgnoreAnnotation]
	if ok {
		return r.setCondition(ctx, oob, nil, nil, metalv1alpha1.OOBStateIgnored, metav1.Condition{
			Type:   metalv1alpha1.OOBConditionTypeReady,
			Status: metav1.ConditionFalse,
			Reason: metalv1alpha1.OOBConditionReasonIgnored,
		})
	} else if oob.Status.State == metalv1alpha1.OOBStateIgnored {
		return r.setCondition(ctx, oob, nil, nil, metalv1alpha1.OOBStateInProgress, metav1.Condition{
			Type:   metalv1alpha1.OOBConditionTypeReady,
			Status: metav1.ConditionFalse,
			Reason: metalv1alpha1.OOBConditionReasonInProgress,
		})
	}

	return ctx, nil, nil, nil
}

func (r *OOBReconciler) processInitial(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration

	ctx = log.WithValues(ctx, "mac", oob.Spec.MACAddress)

	if !controllerutil.ContainsFinalizer(oob, OOBFinalizer) {
		var err error
		apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
		}
		apply.Finalizers = util.Set(apply.Finalizers, OOBFinalizer)
	}

	_, ok := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if oob.Status.State == "" || !ok {
		return r.setCondition(ctx, oob, apply, nil, metalv1alpha1.OOBStateInProgress, metav1.Condition{
			Type:   metalv1alpha1.OOBConditionTypeReady,
			Status: metav1.ConditionFalse,
			Reason: metalv1alpha1.OOBConditionReasonInProgress,
		})
	}

	return ctx, apply, nil, nil
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
					return ctx, nil, nil, fmt.Errorf("cannot extract IP: %w", err)
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
				return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
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
					return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithEndpointRef(*oob.Spec.EndpointRef))

			ctx, apply, status, err = r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
			if err != nil {
				return ctx, nil, nil, err
			}

			break
		}
		if !found {
			return r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateNoEndpoint, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonNoEndpoint,
			})
		}
	}

	if !controllerutil.ContainsFinalizer(&ip, OOBFinalizer) {
		log.Debug(ctx, "Adding finalizer to IP")
		ipApply, err := ipamv1alpha1apply.ExtractIP(&ip, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot extract IP: %w", err)
		}
		ipApply.Finalizers = util.Set(ipApply.Finalizers, OOBFinalizer)
		err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot apply IP: %w", err)
		}
	}

	if ip.Labels[OOBIPMacLabel] != oob.Spec.MACAddress {
		return r.setError(ctx, oob, apply, status, OOBErrorBadEndpoint, fmt.Errorf("endpoint has incorrect MAC address: expected %s, actual %s", oob.Spec.MACAddress, ip.Labels[OOBIPMacLabel]))
	}

	if ip.Status.State != ipamv1alpha1.CFinishedIPState || ip.Status.Reserved == nil || !ip.Status.Reserved.Net.IsValid() {
		return r.setError(ctx, oob, apply, status, OOBErrorBadEndpoint, fmt.Errorf("endpoint has no valid IP address"))
	}

	if oob.Status.State == metalv1alpha1.OOBStateError {
		cond, _ := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
		if strings.HasPrefix(cond.Message, OOBErrorBadEndpoint+": ") {
			return r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
		}
	}

	return context.WithValue(ctx, ctxkOOBHost{}, ip.Status.Reserved.String()), apply, status, nil
}

func (r *OOBReconciler) processCredentials(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration

	var defaultCreds []bmc.Credentials
	var creds bmc.Credentials
	var expiration time.Time
	now := time.Now()

	var secret metalv1alpha1.OOBSecret
	if oob.Spec.SecretRef != nil {
		err := r.Get(ctx, client.ObjectKey{
			Name: oob.Spec.SecretRef.Name,
		}, &secret)
		if err != nil && !errors.IsNotFound(err) {
			return ctx, nil, nil, fmt.Errorf("cannot get OOBSecret: %w", err)
		}

		if errors.IsNotFound(err) {
			oob.Spec.SecretRef = nil

			apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec))
			apply.Spec.SecretRef = nil
		} else {
			ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

			valid := secret.Spec.MACAddress == oob.Spec.MACAddress && (secret.Spec.Username != "" || secret.Spec.Password != "")
			if !valid {
				if secret.Spec.MACAddress != oob.Spec.MACAddress {
					err = fmt.Errorf("secret has incorrect MAC address: expected %s, actual %s", oob.Spec.MACAddress, secret.Spec.MACAddress)
				} else {
					err = fmt.Errorf("secret has no valid credentials")
				}
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}

			creds.Username = secret.Spec.Username
			creds.Password = secret.Spec.Password
			if secret.Spec.ExpirationTime != nil {
				expiration = secret.Spec.ExpirationTime.Time
			}
		}
	}
	if oob.Spec.SecretRef == nil {
		var secretList metalv1alpha1.OOBSecretList
		err := r.List(ctx, &secretList, client.MatchingFields{OOBSecretSpecMACAddress: oob.Spec.MACAddress})
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot list OOBSecrets: %w", err)
		}

		if len(secretList.Items) > 1 {
			return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, fmt.Errorf("multiple OOBSecrets for MAC address %s", oob.Spec.MACAddress))
		}

		if len(secretList.Items) == 1 {
			secret = secretList.Items[0]

			oob.Spec.SecretRef = &v1.LocalObjectReference{
				Name: secret.Name,
			}
			ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithSecretRef(*oob.Spec.SecretRef))

			return r.setCondition(ctx, oob, apply, nil, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
		}
	}

	if oob.Spec.Protocol == nil || (creds.Username == "" && creds.Password == "") {
		a, ok := r.macDB.Get(oob.Spec.MACAddress)
		if !ok {
			return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, fmt.Errorf("cannot find MAC address in MAC DB: %s", oob.Spec.MACAddress))
		}

		if a.Ignore && !metav1.HasAnnotation(oob.ObjectMeta, OOBIgnoreAnnotation) {
			if apply == nil {
				var err error
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithAnnotations(map[string]string{
				OOBIgnoreAnnotation: "",
			})

			return ctx, apply, nil, nil
		}

		oob.Spec.Protocol = &a.Protocol
		oob.Spec.Flags = a.Flags
		defaultCreds = a.DefaultCredentials

		if !util.NilOrEqual(oob.Spec.Protocol, &a.Protocol) ||
			!maps.Equal(oob.Spec.Flags, a.Flags) {
			if apply == nil {
				var err error
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithProtocol(metalv1alpha1apply.Protocol().
					WithName(oob.Spec.Protocol.Name).
					WithPort(oob.Spec.Protocol.Port)).
				WithFlags(oob.Spec.Flags))
		}
	}

	b, err := bmc.NewBMC(string(oob.Spec.Protocol.Name), oob.Spec.Flags, ctx.Value(ctxkOOBHost{}).(string), oob.Spec.Protocol.Port, creds, expiration)
	if err != nil {
		return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
	}

	if creds.Username == "" && creds.Password == "" {
		log.Info(ctx, "Ensuring initial credentials")
		err = b.EnsureInitialCredentials(ctx, defaultCreds, r.temporaryPassword)
		if err != nil {
			return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
		}
		creds, _ = b.Credentials()
		expiration = now
	} else {
		err = b.Connect(ctx)
		if err != nil {
			return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
		}
	}

	if !expiration.IsZero() {
		timeToRenew := expiration.Add(-r.credsRenewalTimeBeforeExpiry)
		if !timeToRenew.After(now) {
			log.Info(ctx, "Creating new credentials", "expired", expiration)
			creds.Username, err = password.Generate(6, 0, 0, true, false)
			if err != nil {
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}
			creds.Username = r.usernamePrefix + creds.Username

			creds.Password, err = password.Generate(16, 6, 0, false, true)
			if err != nil {
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}

			var anotherPassword string
			anotherPassword, err = password.Generate(16, 6, 0, false, true)
			if err != nil {
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}

			err = b.CreateUser(ctx, creds, anotherPassword)
			if err != nil {
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}

			creds, expiration = b.Credentials()
			if expiration.IsZero() {
				expiration = time.Now().AddDate(0, 0, 37)
			}
			ctx = log.WithValues(ctx, "expiration", expiration)

			if secret.Name == "" {
				secret.Name = oob.Spec.MACAddress
			}
			var secretApply *metalv1alpha1apply.OOBSecretApplyConfiguration
			secretApply, err = metalv1alpha1apply.ExtractOOBSecret(&secret, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, fmt.Errorf("cannot extract OOBSecret: %w", err)
			}
			secretApply.Finalizers = util.Set(secretApply.Finalizers, OOBFinalizer)
			secretApply = secretApply.WithSpec(util.Ensure(secretApply.Spec).
				WithMACAddress(oob.Spec.MACAddress).
				WithUsername(creds.Username).
				WithPassword(creds.Password).
				WithExpirationTime(metav1.Time{
					Time: expiration,
				}))
			err = r.Patch(ctx, &secret, ssa.Apply(secretApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
			if err != nil {
				return ctx, nil, nil, fmt.Errorf("cannot apply OOBSecret: %w", err)
			}

			oob.Spec.SecretRef = &v1.LocalObjectReference{
				Name: secret.Name,
			}
			ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithSecretRef(*oob.Spec.SecretRef))

			err = b.DeleteUsers(ctx, r.usernameRegex)
			if err != nil {
				return r.setError(ctx, oob, apply, nil, OOBErrorBadCredentials, err)
			}
		}
	}

	if !controllerutil.ContainsFinalizer(&secret, OOBFinalizer) {
		var secretApply *metalv1alpha1apply.OOBSecretApplyConfiguration
		secretApply, err = metalv1alpha1apply.ExtractOOBSecret(&secret, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot extract OOBSecret: %w", err)
		}
		secretApply.Finalizers = util.Set(secretApply.Finalizers, OOBFinalizer)
		err = r.Patch(ctx, &secret, ssa.Apply(secretApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, fmt.Errorf("cannot apply OOBSecret: %w", err)
		}
	}

	if oob.Status.State == metalv1alpha1.OOBStateError {
		cond, _ := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
		if strings.HasPrefix(cond.Message, OOBErrorBadCredentials+": ") {
			return r.setCondition(ctx, oob, apply, nil, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
		}
	}

	return ctx, apply, nil, nil
}

func (r *OOBReconciler) processReady(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, error) {
	return r.setCondition(ctx, oob, nil, nil, metalv1alpha1.OOBStateReady, metav1.Condition{
		Type:   metalv1alpha1.OOBConditionTypeReady,
		Status: metav1.ConditionTrue,
		Reason: metalv1alpha1.OOBConditionReasonReady,
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *OOBReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	c, err := cru.CreateController(mgr, &metalv1alpha1.OOB{}, r)
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &ipamv1alpha1.IP{}), handler.EnqueueRequestsFromMapFunc(r.enqueueOOBFromIP))
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &metalv1alpha1.OOBSecret{}), handler.EnqueueRequestsFromMapFunc(r.enqueueOOBFromOOBSecret))
	if err != nil {
		return err
	}

	return mgr.Add(c)
}

func (r *OOBReconciler) enqueueOOBFromIP(ctx context.Context, obj client.Object) []reconcile.Request {
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

	reqs := make([]reconcile.Request, 0, len(oobList.Items))
	for _, o := range oobList.Items {
		if o.DeletionTimestamp != nil {
			continue
		}

		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Name: o.Name,
		}})
	}

	if len(oobList.Items) == 0 && ip.Status.State == ipamv1alpha1.CFinishedIPState && ip.Status.Reserved != nil {
		_, ok = r.macDB.Get(mac)
		if ok {
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
	}

	return reqs
}

func (r *OOBReconciler) enqueueOOBFromOOBSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret := obj.(*metalv1alpha1.OOBSecret)

	oobList := metalv1alpha1.OOBList{}
	err := r.List(ctx, &oobList, client.MatchingFields{OOBSpecMACAddress: secret.Spec.MACAddress})
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot list OOBs: %w", err))
		return nil
	}

	reqs := make([]reconcile.Request, 0, len(oobList.Items))
	for _, o := range oobList.Items {
		if o.DeletionTimestamp != nil {
			continue
		}

		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Name: o.Name,
		}})
	}

	return reqs
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
