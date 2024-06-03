// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
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
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
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
	OOBUnknownAnnotation    = "metal.ironcore.dev/oob-unknown"
	OOBMacRegex             = `^[0-9A-Fa-f]{12}$`
	OOBUsernameRegexSuffix  = `[a-z]{6}`
	OOBSpecMACAddress       = ".spec.MACAddress"
	OOBSecretSpecMACAddress = ".spec.MACAddress"
	// OOBTemporaryNamespaceHack TODO: Remove temporary namespace hack.
	OOBTemporaryNamespaceHack = "oob"
	OOBErrorBadEndpoint       = "BadEndpoint"
	OOBErrorBadCredentials    = "BadCredentials"
	OOBErrorBadInfo           = "BadInfo"
	OOBErrorBadMachines       = "BadMachines"
	OOBErrorBadMachineControl = "BadMachineControl"
)

func NewOOBReconciler(systemNamespace, ipLabelSelector, macDB string, credsRenewalBeforeExpiry, shutdownTimeout time.Duration, usernamePrefix, temporaryPasswordSecret string) (*OOBReconciler, error) {
	r := &OOBReconciler{
		systemNamespace:              systemNamespace,
		credsRenewalTimeBeforeExpiry: credsRenewalBeforeExpiry,
		shutdownTimeout:              shutdownTimeout,
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
	shutdownTimeout              time.Duration
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
	Type               metalv1alpha1.OOBType  `yaml:"type"`
}

type ctxkOOBHost struct{}
type ctxkBMC struct{}
type ctxkInfo struct{}
type ctxkMachines struct{}

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

	err = r.finalizeSecret(ctx, oob)
	if err != nil {
		return err
	}

	err = r.finalizeMachines(ctx, oob)
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

func (r *OOBReconciler) finalizeMachines(ctx context.Context, oob *metalv1alpha1.OOB) error {
	var machineList metalv1alpha1.MachineList
	err := r.List(ctx, &machineList, client.MatchingFields{
		MachineSpecOOBRefName: oob.Name,
	})
	if err != nil {
		return fmt.Errorf("cannot list Machines: %w", err)
	}
	for _, m := range machineList.Items {
		log.Info(ctx, "Deleting machine", "machine", m.Name)
		err = r.Delete(ctx, &m)
		if err != nil {
			return fmt.Errorf("cannot delete Machine: %w", err)
		}
	}

	return nil
}

func (r *OOBReconciler) reconcile(ctx context.Context, oob *metalv1alpha1.OOB) (ctrl.Result, error) {
	log.Debug(ctx, "Reconciling")

	var advance bool
	var requeueAfter time.Duration
	var err error

	phases := []oobRecPhase{
		{
			name:         "Ignored",
			run:          r.reconcileIgnored,
			readyReasons: []string{metalv1alpha1.OOBConditionReasonIgnored},
		},
		{
			name: "Initial",
			run:  r.reconcileInitial,
		},
		{
			name:         "Endpoint",
			run:          r.reconcileEndpoint,
			errType:      OOBErrorBadEndpoint,
			readyReasons: []string{metalv1alpha1.OOBConditionReasonNoEndpoint},
		},
		{
			name:    "Credentials",
			run:     r.reconcileCredentials,
			errType: OOBErrorBadCredentials,
		},
		{
			name:    "Info",
			run:     r.reconcileInfo,
			errType: OOBErrorBadInfo,
		},
		{
			name:    "Machines",
			run:     r.reconcileMachines,
			errType: OOBErrorBadMachines,
		},
		{
			name:    "MachineControl",
			run:     r.reconcileMachineControl,
			errType: OOBErrorBadMachineControl,
		},
		{
			name:         "Ready",
			run:          r.reconcileReady,
			readyReasons: []string{metalv1alpha1.OOBConditionReasonReady},
		},
	}

	for _, p := range phases {
		ctx, advance, requeueAfter, err = r.runPhase(ctx, oob, p)
		if !advance {
			return ctrl.Result{
				RequeueAfter: requeueAfter,
			}, err
		}
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
}

type oobRecPhase struct {
	name         string
	run          func(context.Context, *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error)
	errType      string
	readyReasons []string
}

func (r *OOBReconciler) runPhase(ctx context.Context, oob *metalv1alpha1.OOB, phase oobRecPhase) (context.Context, bool, time.Duration, error) {
	ctx = log.WithValues(ctx, "phase", phase.name)
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration
	var requeueAfter time.Duration
	var err error

	if phase.run == nil {
		return ctx, true, 0, nil
	}

	ctx, apply, status, requeueAfter, err = phase.run(ctx, oob)
	if err != nil {
		return ctx, false, 0, err
	}

	if apply != nil {
		log.Debug(ctx, "Applying")
		err = r.Patch(ctx, oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, 0, fmt.Errorf("cannot apply OOB: %w", err)
		}
	}

	if status != nil {
		apply = metalv1alpha1apply.OOB(oob.Name, oob.Namespace).WithStatus(status)

		log.Debug(ctx, "Applying status")
		err = r.Status().Patch(ctx, oob, ssa.Apply(apply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, false, 0, fmt.Errorf("cannot apply OOB status: %w", err)
		}
	}

	advance := true
	cond, ok := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if ok {
		if cond.Reason == metalv1alpha1.OOBConditionReasonError && strings.HasPrefix(cond.Message, phase.errType+": ") {
			return ctx, false, 0, fmt.Errorf(cond.Message)
		}
		if slices.Contains(phase.readyReasons, cond.Reason) {
			advance = false
		}
	}

	advance = advance && apply == nil && requeueAfter == 0
	if !advance {
		log.Debug(ctx, "Reconciled successfully")
	}
	return ctx, advance, requeueAfter, nil
}

func (r *OOBReconciler) setCondition(ctx context.Context, oob *metalv1alpha1.OOB, apply *metalv1alpha1apply.OOBApplyConfiguration, status *metalv1alpha1apply.OOBStatusApplyConfiguration, state metalv1alpha1.OOBState, cond metav1.Condition) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	conds, mod := ssa.SetCondition(oob.Status.Conditions, cond)
	if oob.Status.State != state || mod {
		log.Debug(ctx, "Setting condition", "type", cond.Type, "status", cond.Status, "reason", cond.Reason)
		if status == nil {
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB status: %w", err)
			}
			status = util.Ensure(applyst.Status)
		}
		status = status.WithState(state)
		status.Conditions = nil
		for _, c := range conds {
			ca := metav1apply.Condition().
				WithType(c.Type).
				WithStatus(c.Status).
				WithLastTransitionTime(c.LastTransitionTime).
				WithReason(c.Reason).
				WithMessage(c.Message)
			status = status.WithConditions(ca)
		}
	}
	return ctx, apply, status, 0, nil
}

func (r *OOBReconciler) setError(ctx context.Context, oob *metalv1alpha1.OOB, apply *metalv1alpha1apply.OOBApplyConfiguration, status *metalv1alpha1apply.OOBStatusApplyConfiguration, errType string, err error) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
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

func (r *OOBReconciler) reconcileIgnored(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
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

	return ctx, nil, nil, 0, nil
}

func (r *OOBReconciler) reconcileInitial(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration

	ctx = log.WithValues(ctx, "mac", oob.Spec.MACAddress)

	if !controllerutil.ContainsFinalizer(oob, OOBFinalizer) {
		log.Debug(ctx, "Adding finalizer")
		var err error
		apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
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

	return ctx, apply, nil, 0, nil
}

func (r *OOBReconciler) reconcileEndpoint(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration

	var ip ipamv1alpha1.IP
	if oob.Spec.EndpointRef != nil {
		err := r.Get(ctx, client.ObjectKey{
			Namespace: OOBTemporaryNamespaceHack,
			Name:      oob.Spec.EndpointRef.Name,
		}, &ip)
		if err != nil && !errors.IsNotFound(err) {
			return ctx, nil, nil, 0, fmt.Errorf("cannot get IP: %w", err)
		}

		valid := ip.DeletionTimestamp == nil && r.ipLabelSelector.Matches(labels.Set(ip.Labels)) && ip.Namespace == OOBTemporaryNamespaceHack
		if errors.IsNotFound(err) || !valid {
			if !valid && controllerutil.ContainsFinalizer(&ip, OOBFinalizer) {
				log.Debug(ctx, "Removing finalizer from IP")
				var ipApply *ipamv1alpha1apply.IPApplyConfiguration
				ipApply, err = ipamv1alpha1apply.ExtractIP(&ip, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract IP: %w", err)
				}
				ipApply.Finalizers = util.Clear(ipApply.Finalizers, OOBFinalizer)
				err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot apply IP: %w", err)
				}
			}

			oob.Spec.EndpointRef = nil

			log.Debug(ctx, "Clearing endpoint ref")
			apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
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
			return ctx, nil, nil, 0, fmt.Errorf("cannot list IPs: %w", err)
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

			log.Debug(ctx, "Setting endpoint ref")
			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithEndpointRef(*oob.Spec.EndpointRef))

			ctx, apply, status, _, err = r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
			if err != nil {
				return ctx, nil, nil, 0, err
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
			return ctx, nil, nil, 0, fmt.Errorf("cannot extract IP: %w", err)
		}
		ipApply.Finalizers = util.Set(ipApply.Finalizers, OOBFinalizer)
		err = r.Patch(ctx, &ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot apply IP: %w", err)
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

	return context.WithValue(ctx, ctxkOOBHost{}, ip.Status.Reserved.String()), apply, status, 0, nil
}

func (r *OOBReconciler) reconcileCredentials(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	host := ctx.Value(ctxkOOBHost{}).(string)

	var apply *metalv1alpha1apply.OOBApplyConfiguration
	var status *metalv1alpha1apply.OOBStatusApplyConfiguration

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
			return ctx, nil, nil, 0, fmt.Errorf("cannot get OOBSecret: %w", err)
		}

		if errors.IsNotFound(err) {
			oob.Spec.SecretRef = nil

			log.Debug(ctx, "Clearing secret ref")
			apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
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
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, err)
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
		err := r.List(ctx, &secretList, client.MatchingFields{
			OOBSecretSpecMACAddress: oob.Spec.MACAddress,
		})
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot list OOBSecrets: %w", err)
		}

		if len(secretList.Items) > 1 {
			return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("multiple OOBSecrets for MAC address %s", oob.Spec.MACAddress))
		}

		if len(secretList.Items) == 1 {
			secret = secretList.Items[0]

			oob.Spec.SecretRef = &v1.LocalObjectReference{
				Name: secret.Name,
			}
			ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

			log.Debug(ctx, "Setting secret ref")
			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithSecretRef(*oob.Spec.SecretRef))

			return r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
		}
	}

	if oob.Spec.Protocol == nil || oob.Status.Type == "" || (creds.Username == "" && creds.Password == "") {
		a, ok := r.macDB.Get(oob.Spec.MACAddress)
		if !ok {
			return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot find MAC address in MAC DB: %s", oob.Spec.MACAddress))
		}
		defaultCreds = a.DefaultCredentials

		if a.Ignore && !metav1.HasAnnotation(oob.ObjectMeta, OOBIgnoreAnnotation) {
			log.Debug(ctx, "Adding ignore annotation")
			if apply == nil {
				var err error
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithAnnotations(map[string]string{
				OOBIgnoreAnnotation: "",
			})

			return ctx, apply, status, 0, nil
		}

		if !util.NilOrEqual(oob.Spec.Protocol, &a.Protocol) {
			oob.Spec.Protocol = &a.Protocol
			oob.Spec.Flags = a.Flags
			log.Debug(ctx, "Setting protocol and flags")
			if apply == nil {
				var err error
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithProtocol(metalv1alpha1apply.Protocol().
					WithName(oob.Spec.Protocol.Name).
					WithPort(oob.Spec.Protocol.Port)).
				WithFlags(oob.Spec.Flags))
		}

		if oob.Status.Type != a.Type {
			oob.Status.Type = a.Type
			log.Debug(ctx, "Setting type")
			applyst, err := metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB status: %w", err)
			}
			status = util.Ensure(applyst.Status).
				WithType(a.Type)
		}
	}

	b, err := bmc.NewBMC(string(oob.Spec.Protocol.Name), oob.Spec.Flags, host, oob.Spec.Protocol.Port, creds, expiration)
	if err != nil {
		return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot initialize BMC: %w", err))
	}

	if creds.Username == "" && creds.Password == "" {
		log.Info(ctx, "Ensuring initial credentials")
		err = b.EnsureInitialCredentials(ctx, defaultCreds, r.temporaryPassword)
		if err != nil {
			return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot ensure initial credentials: %w", err))
		}
		creds, _ = b.Credentials()
		expiration = now
	} else {
		err = b.Connect(ctx)
		if err != nil {
			return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot connect to BMC: %w", err))
		}
	}

	if !expiration.IsZero() {
		timeToRenew := expiration.Add(-r.credsRenewalTimeBeforeExpiry)
		if !timeToRenew.After(now) {
			log.Info(ctx, "Creating new credentials", "expired", expiration)
			creds.Username, err = password.Generate(6, 0, 0, true, false)
			if err != nil {
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot generate credentials: %w", err))
			}
			creds.Username = r.usernamePrefix + creds.Username

			creds.Password, err = password.Generate(16, 6, 0, false, true)
			if err != nil {
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot generate credentials: %w", err))
			}

			var anotherPassword string
			anotherPassword, err = password.Generate(16, 6, 0, false, true)
			if err != nil {
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot generate credentials: %w", err))
			}

			err = b.CreateUser(ctx, creds, anotherPassword)
			if err != nil {
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot create user: %w", err))
			}

			creds, expiration = b.Credentials()
			if expiration.IsZero() {
				expiration = time.Now().AddDate(0, 0, 37)
			}
			ctx = log.WithValues(ctx, "expiration", expiration)

			if secret.Name == "" {
				secret.Name = oob.Spec.MACAddress
			}
			log.Debug(ctx, "Adding finalizer to OOBSecret and setting MAC, credentials, and expiration")
			var secretApply *metalv1alpha1apply.OOBSecretApplyConfiguration
			secretApply, err = metalv1alpha1apply.ExtractOOBSecret(&secret, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOBSecret: %w", err)
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
				return ctx, nil, nil, 0, fmt.Errorf("cannot apply OOBSecret: %w", err)
			}

			oob.Spec.SecretRef = &v1.LocalObjectReference{
				Name: secret.Name,
			}
			ctx = log.WithValues(ctx, "secret", oob.Spec.SecretRef.Name)

			log.Debug(ctx, "Setting secret ref")
			if apply == nil {
				apply, err = metalv1alpha1apply.ExtractOOB(oob, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB: %w", err)
				}
			}
			apply = apply.WithSpec(util.Ensure(apply.Spec).
				WithSecretRef(*oob.Spec.SecretRef))

			err = b.DeleteUsers(ctx, r.usernameRegex)
			if err != nil {
				return r.setError(ctx, oob, apply, status, OOBErrorBadCredentials, fmt.Errorf("cannot delete users: %w", err))
			}
		}
	}

	if !controllerutil.ContainsFinalizer(&secret, OOBFinalizer) {
		log.Debug(ctx, "Adding finalizer to OOBSecret")
		var secretApply *metalv1alpha1apply.OOBSecretApplyConfiguration
		secretApply, err = metalv1alpha1apply.ExtractOOBSecret(&secret, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOBSecret: %w", err)
		}
		secretApply.Finalizers = util.Set(secretApply.Finalizers, OOBFinalizer)
		err = r.Patch(ctx, &secret, ssa.Apply(secretApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot apply OOBSecret: %w", err)
		}
	}

	if oob.Status.State == metalv1alpha1.OOBStateError {
		cond, _ := ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
		if strings.HasPrefix(cond.Message, OOBErrorBadCredentials+": ") {
			return r.setCondition(ctx, oob, apply, status, metalv1alpha1.OOBStateInProgress, metav1.Condition{
				Type:   metalv1alpha1.OOBConditionTypeReady,
				Status: metav1.ConditionFalse,
				Reason: metalv1alpha1.OOBConditionReasonInProgress,
			})
		}
	}

	return context.WithValue(ctx, ctxkBMC{}, b), apply, status, 0, nil
}

func (r *OOBReconciler) reconcileInfo(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	b := ctx.Value(ctxkBMC{}).(bmc.BMC)

	var status *metalv1alpha1apply.OOBStatusApplyConfiguration

	log.Info(ctx, "Reading BMC info")
	info, err := b.ReadInfo(ctx)
	if err != nil {
		return r.setError(ctx, oob, nil, status, OOBErrorBadInfo, fmt.Errorf("cannot read BMC info: %w", err))
	}

	if oob.Status.Manufacturer != info.Manufacturer ||
		oob.Status.SerialNumber != info.SerialNumber ||
		oob.Status.FirmwareVersion != info.FirmwareVersion {
		log.Debug(ctx, "Setting manufacturer, serial number, and firmware version")
		var applyst *metalv1alpha1apply.OOBApplyConfiguration
		applyst, err = metalv1alpha1apply.ExtractOOBStatus(oob, OOBFieldManager)
		if err != nil {
			return ctx, nil, nil, 0, fmt.Errorf("cannot extract OOB status: %w", err)
		}
		status = util.Ensure(applyst.Status).
			WithManufacturer(info.Manufacturer).
			WithSerialNumber(info.SerialNumber).
			WithFirmwareVersion(info.FirmwareVersion)
	}

	return context.WithValue(ctx, ctxkInfo{}, info), nil, status, 0, nil
}

func (r *OOBReconciler) reconcileMachines(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	info := ctx.Value(ctxkInfo{}).(bmc.Info)

	type minfo struct {
		m *metalv1alpha1.Machine
		i bmc.Machine
	}
	machineInfos := make(map[string]minfo, len(info.Machines))
	if oob.Status.Type == metalv1alpha1.OOBTypeMachine {
		for _, i := range info.Machines {
			machineInfos[i.UUID] = minfo{
				m: nil,
				i: i,
			}
		}
	}

	var machineList metalv1alpha1.MachineList
	err := r.List(ctx, &machineList, client.MatchingFields{
		MachineSpecOOBRefName: oob.Name,
	})
	if err != nil {
		return ctx, nil, nil, 0, fmt.Errorf("cannot list Machines: %w", err)
	}
	for _, m := range machineList.Items {
		mi, ok := machineInfos[m.Spec.UUID]
		if !ok {
			log.Info(ctx, "Deleting orphaned machine", "machine", m.Name)
			err = r.Delete(ctx, &m)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot delete Machine: %w", err)
			}
			continue
		}

		machine := &m
		machineInfos[m.Spec.UUID] = minfo{
			m: machine,
			i: mi.i,
		}
	}

	oobRef := v1.LocalObjectReference{
		Name: oob.Name,
	}

	machines := make([]*metalv1alpha1.Machine, 0, len(machineInfos))
	for uuid, mi := range machineInfos {
		var machineApply *metalv1alpha1apply.MachineApplyConfiguration

		if mi.m == nil {
			mi.m = &metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Name: uuid,
				},
			}
			machineApply = metalv1alpha1apply.Machine(mi.m.Name, "").WithSpec(metalv1alpha1apply.MachineSpec().
				WithUUID(uuid).
				WithOOBRef(oobRef))
		}

		op, ok := mi.m.Annotations[metalv1alpha1.MachineOperationKeyName]
		if ok && op == "" {
			machineApply, err = metalv1alpha1apply.ExtractMachine(mi.m, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract Machine: %w", err)
			}
			_, ok = machineApply.Annotations[metalv1alpha1.MachineOperationKeyName]
			if ok {
				delete(machineApply.Annotations, metalv1alpha1.MachineOperationKeyName)
			} else {
				machineApply = nil
			}
		}

		if machineApply != nil {
			log.Info(ctx, "Applying Machine", "machine", mi.m.Name)
			err = r.Patch(ctx, mi.m, ssa.Apply(machineApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot apply Machine: %w", err)
			}
		}

		if mi.m.Status.Manufacturer != mi.i.Manufacturer ||
			mi.m.Status.SKU != mi.i.SKU ||
			mi.m.Status.SerialNumber != mi.i.SerialNumber ||
			mi.m.Status.Power != metalv1alpha1.Power(mi.i.Power) ||
			mi.m.Status.LocatorLED != metalv1alpha1.LED(mi.i.LocatorLED) {
			machineApply, err = metalv1alpha1apply.ExtractMachineStatus(mi.m, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot extract Machine status: %w", err)
			}
			machineApply = machineApply.WithStatus(util.Ensure(machineApply.Status).
				WithManufacturer(mi.i.Manufacturer).
				WithSKU(mi.i.SKU).
				WithSerialNumber(mi.i.SerialNumber))
			if mi.i.Power != "" {
				machineApply.Status = machineApply.Status.WithPower(metalv1alpha1.Power(mi.i.Power))
			}
			if mi.i.LocatorLED != "" {
				machineApply.Status = machineApply.Status.WithLocatorLED(metalv1alpha1.LED(mi.i.LocatorLED))
			}
			log.Info(ctx, "Applying Machine status", "machine", mi.m.Name)
			err = r.Status().Patch(ctx, mi.m, ssa.Apply(machineApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
			if err != nil {
				return ctx, nil, nil, 0, fmt.Errorf("cannot apply Machine status: %w", err)
			}
		}

		machines = append(machines, mi.m)
	}
	return context.WithValue(ctx, ctxkMachines{}, machines), nil, nil, 0, nil
}

func (r *OOBReconciler) reconcileMachineControl(ctx context.Context, _ *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
	b := ctx.Value(ctxkBMC{}).(bmc.BMC)
	machines := ctx.Value(ctxkMachines{}).([]*metalv1alpha1.Machine)

	phases := []machineCtrlPhase{
		{
			name: "LocatorLED",
			run:  r.controlLocatorLED,
		},
		{
			name: "Power",
			run:  r.controlPower,
		},
		{
			name: "Restart",
			run:  r.controlRestart,
		},
		{
			name: "Ready",
			run:  r.controlReady,
		},
	}

	var requeueAfter time.Duration
	for _, p := range phases {
		next := make([]*metalv1alpha1.Machine, 0, len(machines))
		for _, m := range machines {
			advance, ra, err := r.runCtrlPhase(log.WithValues(ctx, "ctrlPhase", p.name, "machine", m.Name), m, b, p)
			if err != nil {
				return ctx, nil, nil, 0, err
			}
			if advance {
				next = append(next, m)
			}
			if ra > 0 {
				if requeueAfter == 0 || ra < requeueAfter {
					requeueAfter = ra
				}
			}
		}
		machines = next
	}

	return ctx, nil, nil, requeueAfter, nil
}

type machineCtrlPhase struct {
	name string
	run  func(context.Context, *metalv1alpha1.Machine, bmc.BMC) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error)
}

func (r *OOBReconciler) runCtrlPhase(ctx context.Context, machine *metalv1alpha1.Machine, b bmc.BMC, phase machineCtrlPhase) (bool, time.Duration, error) {
	var machineApply *metalv1alpha1apply.MachineApplyConfiguration
	var machineStatus *metalv1alpha1apply.MachineStatusApplyConfiguration
	var advance bool
	var requeueAfter time.Duration
	var err error

	if phase.run == nil {
		return true, 0, nil
	}

	ctx, machineApply, machineStatus, advance, requeueAfter, err = phase.run(ctx, machine, b)
	if err != nil {
		return false, 0, err
	}

	if machineApply != nil {
		log.Debug(ctx, "Applying Machine")
		err = r.Patch(ctx, machine, ssa.Apply(machineApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return false, 0, fmt.Errorf("cannot apply Machine: %w", err)
		}
	}

	if machineStatus != nil {
		machineApply = metalv1alpha1apply.Machine(machine.Name, machine.Namespace).WithStatus(machineStatus)

		log.Debug(ctx, "Applying Machine status")
		err = r.Status().Patch(ctx, machine, ssa.Apply(machineApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
		if err != nil {
			return false, 0, fmt.Errorf("cannot apply Machine status: %w", err)
		}
	}

	return advance && machineApply == nil, requeueAfter, nil
}

func (r *OOBReconciler) setMachineCondition(ctx context.Context, machine *metalv1alpha1.Machine, machineApply *metalv1alpha1apply.MachineApplyConfiguration, machineStatus *metalv1alpha1apply.MachineStatusApplyConfiguration, advance bool, requeueAfter time.Duration, cond metav1.Condition) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	conds, mod := ssa.SetCondition(machine.Status.Conditions, cond)
	if mod {
		if machineStatus == nil {
			applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
			}
			machineStatus = util.Ensure(applyst.Status)
		}

		log.Debug(ctx, "Setting Machine condition", "type", cond.Type, "status", cond.Status, "reason", cond.Reason)
		machineStatus.Conditions = nil
		for _, c := range conds {
			ca := metav1apply.Condition().
				WithType(c.Type).
				WithStatus(c.Status).
				WithLastTransitionTime(c.LastTransitionTime).
				WithReason(c.Reason).
				WithMessage(c.Message)
			machineStatus = machineStatus.WithConditions(ca)
		}
	}
	return ctx, machineApply, machineStatus, advance, requeueAfter, nil
}

func (r *OOBReconciler) setMachineError(ctx context.Context, machine *metalv1alpha1.Machine, machineApply *metalv1alpha1apply.MachineApplyConfiguration, machineStatus *metalv1alpha1apply.MachineStatusApplyConfiguration, err error) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	return r.setMachineCondition(ctx, machine, machineApply, machineStatus, false, 0, metav1.Condition{
		Type:    metalv1alpha1.MachineConditionTypeOOBHealthy,
		Status:  metav1.ConditionFalse,
		Reason:  metalv1alpha1.MachineConditionReasonOOBError,
		Message: err.Error(),
	})
}

func (r *OOBReconciler) controlLocatorLED(ctx context.Context, machine *metalv1alpha1.Machine, b bmc.BMC) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	if machine.Spec.LocatorLED == "" {
		return ctx, nil, nil, true, 0, nil
	}

	lc, ok := b.(bmc.LEDControl)
	if !ok {
		return r.setMachineError(ctx, machine, nil, nil, fmt.Errorf("BMC does not support LED control"))
	}

	if machine.Spec.LocatorLED == machine.Status.LocatorLED {
		return ctx, nil, nil, true, 0, nil
	}

	log.Info(ctx, "Setting machine locator LED", "locatorLED", machine.Spec.LocatorLED)
	led, err := lc.SetLocatorLED(ctx, machine.Spec.UUID, bmc.LED(machine.Spec.LocatorLED))
	if err != nil {
		return r.setMachineError(ctx, machine, nil, nil, fmt.Errorf("cannot set Machine locator LED: %w", err))
	}

	var applyst *metalv1alpha1apply.MachineApplyConfiguration
	applyst, err = metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
	if err != nil {
		return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
	}
	machineStatus := util.Ensure(applyst.Status).
		WithLocatorLED(metalv1alpha1.LED(led))
	return ctx, nil, machineStatus, true, 0, nil
}

func (r *OOBReconciler) controlPower(ctx context.Context, machine *metalv1alpha1.Machine, b bmc.BMC) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	var machineApply *metalv1alpha1apply.MachineApplyConfiguration
	var machineStatus *metalv1alpha1apply.MachineStatusApplyConfiguration
	var requeueAfter time.Duration

	if machine.Spec.Power == "" {
		return ctx, machineApply, machineStatus, true, requeueAfter, nil
	}
	op := machine.Annotations[metalv1alpha1.MachineOperationKeyName]

	pc, ok := b.(bmc.PowerControl)
	if !ok {
		if machine.Status.ShutdownDeadline != nil {
			applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
			}
			machineStatus = util.Ensure(applyst.Status)
			machineStatus.ShutdownDeadline = nil
		}
		return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("BMC does not support power control"))
	}

	switch machine.Spec.Power {
	case metalv1alpha1.PowerOn:
		if machine.Status.ShutdownDeadline != nil {
			applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
			}
			machineStatus = util.Ensure(applyst.Status)
			machineStatus.ShutdownDeadline = nil
		}

		switch machine.Status.Power {
		case metalv1alpha1.PowerOn:

		case metalv1alpha1.PowerOff:
			log.Info(ctx, "Setting machine power", "power", "On")
			err := pc.PowerOn(ctx, machine.Spec.UUID)
			if err != nil {
				return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("cannot power machine on: %w", err))
			}
			requeueAfter = time.Second

		default:
			return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("unsupported power state: %s", machine.Status.Power))
		}

	case metalv1alpha1.PowerOff:
		switch machine.Status.Power {
		case metalv1alpha1.PowerOn:
			now := time.Now()
			force := op == metalv1alpha1.MachineOperationForceOff
			if !force && machine.Status.ShutdownDeadline.IsZero() {
				applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
				}
				machineStatus = util.Ensure(applyst.Status).
					WithShutdownDeadline(metav1.Time{Time: now.Add(r.shutdownTimeout)})

				log.Info(ctx, "Setting machine power", "power", "On", "force", false)
				err = pc.PowerOff(ctx, machine.Spec.UUID, false)
				if err != nil {
					return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("cannot power machine off: %w", err))
				}
			} else if force || !machine.Status.ShutdownDeadline.After(now) {
				applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
				}
				machineStatus = util.Ensure(applyst.Status)
				machineStatus.ShutdownDeadline = nil

				log.Info(ctx, "Setting machine power", "power", "On", "force", true)
				err = pc.PowerOff(ctx, machine.Spec.UUID, true)
				if err != nil {
					return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("cannot power machine off: %w", err))
				}

				machineApply, err = metalv1alpha1apply.ExtractMachine(machine, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine: %w", err)
				}
				machineApply = machineApply.WithAnnotations(map[string]string{
					metalv1alpha1.MachineOperationKeyName: "",
				})
			} else {
				requeueAfter = time.Second * 3
			}

		case metalv1alpha1.PowerOff:
			if !machine.Status.ShutdownDeadline.IsZero() {
				applyst, err := metalv1alpha1apply.ExtractMachineStatus(machine, OOBFieldManager)
				if err != nil {
					return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine status: %w", err)
				}
				machineStatus = util.Ensure(applyst.Status)
				machineStatus.ShutdownDeadline = nil
			}

		default:
			return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("unsupported power state: %s", machine.Status.Power))
		}

		if op == metalv1alpha1.MachineOperationRestart || op == metalv1alpha1.MachineOperationForceRestart {
			var err error
			machineApply, err = metalv1alpha1apply.ExtractMachine(machine, OOBFieldManager)
			if err != nil {
				return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine: %w", err)
			}
			machineApply = machineApply.WithAnnotations(map[string]string{
				metalv1alpha1.MachineOperationKeyName: "",
			})
		}

	default:
		return r.setMachineError(ctx, machine, machineApply, machineStatus, fmt.Errorf("unsupported power state: %s", machine.Status.Power))
	}

	return ctx, machineApply, machineStatus, true, requeueAfter, nil
}

func (r *OOBReconciler) controlRestart(ctx context.Context, machine *metalv1alpha1.Machine, b bmc.BMC) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	var machineApply *metalv1alpha1apply.MachineApplyConfiguration

	op := machine.Annotations[metalv1alpha1.MachineOperationKeyName]
	if op != metalv1alpha1.MachineOperationRestart && op != metalv1alpha1.MachineOperationForceRestart {
		return ctx, machineApply, nil, true, 0, nil
	}

	rc, ok := b.(bmc.RestartControl)
	if !ok {
		return r.setMachineError(ctx, machine, machineApply, nil, fmt.Errorf("BMC does not support restart control"))
	}

	force := op == metalv1alpha1.MachineOperationForceRestart
	log.Info(ctx, "Restarting machine", "force", force)
	err := rc.Restart(ctx, machine.Spec.UUID, force)
	if err != nil {
		return r.setMachineError(ctx, machine, machineApply, nil, fmt.Errorf("cannot restart machine: %w", err))
	}

	machineApply, err = metalv1alpha1apply.ExtractMachine(machine, OOBFieldManager)
	if err != nil {
		return ctx, nil, nil, false, 0, fmt.Errorf("cannot extract Machine: %w", err)
	}
	machineApply = machineApply.WithAnnotations(map[string]string{
		metalv1alpha1.MachineOperationKeyName: "",
	})

	return ctx, machineApply, nil, true, 0, nil
}

func (r *OOBReconciler) controlReady(ctx context.Context, machine *metalv1alpha1.Machine, _ bmc.BMC) (context.Context, *metalv1alpha1apply.MachineApplyConfiguration, *metalv1alpha1apply.MachineStatusApplyConfiguration, bool, time.Duration, error) {
	return r.setMachineCondition(ctx, machine, nil, nil, true, 0, metav1.Condition{
		Type:   metalv1alpha1.MachineConditionTypeOOBHealthy,
		Status: metav1.ConditionTrue,
		Reason: metalv1alpha1.MachineConditionReasonOOBReady,
	})
}

func (r *OOBReconciler) reconcileReady(ctx context.Context, oob *metalv1alpha1.OOB) (context.Context, *metalv1alpha1apply.OOBApplyConfiguration, *metalv1alpha1apply.OOBStatusApplyConfiguration, time.Duration, error) {
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

	err = c.Watch(source.Kind(mgr.GetCache(), &ipamv1alpha1.IP{}, handler.TypedEnqueueRequestsFromMapFunc(r.enqueueOOBFromIP)))
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &metalv1alpha1.OOBSecret{}, handler.TypedEnqueueRequestsFromMapFunc(r.enqueueOOBFromOOBSecret)))
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &metalv1alpha1.Machine{}, handler.TypedEnqueueRequestsFromMapFunc(r.enqueueOOBFromMachine)))
	if err != nil {
		return err
	}

	return mgr.Add(c)
}

func (r *OOBReconciler) enqueueOOBFromIP(ctx context.Context, ip *ipamv1alpha1.IP) []reconcile.Request {
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
	ctx = log.WithValues(ctx, "mac", mac)

	var oobList metalv1alpha1.OOBList
	err := r.List(ctx, &oobList, client.MatchingFields{
		OOBSpecMACAddress: mac,
	})
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
			if metav1.HasAnnotation(ip.ObjectMeta, OOBUnknownAnnotation) {
				log.Debug(ctx, "Removing unknown annotation from IP")
				var ipApply *ipamv1alpha1apply.IPApplyConfiguration
				ipApply, err = ipamv1alpha1apply.ExtractIP(ip, OOBFieldManager)
				if err != nil {
					log.Error(ctx, fmt.Errorf("cannot extract IP: %w", err))
					return nil
				}
				ipApply.Annotations = nil
				err = r.Patch(ctx, ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
				if err != nil {
					log.Error(ctx, fmt.Errorf("cannot apply IP: %w", err))
					return nil
				}
			}

			log.Info(ctx, "Creating OOB")
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
				return nil
			}
		} else if !metav1.HasAnnotation(ip.ObjectMeta, OOBUnknownAnnotation) {
			log.Debug(ctx, "Adding unknown annotation to IP")
			ip = ip.DeepCopy()
			var ipApply *ipamv1alpha1apply.IPApplyConfiguration
			ipApply, err = ipamv1alpha1apply.ExtractIP(ip, OOBFieldManager)
			if err != nil {
				log.Error(ctx, fmt.Errorf("cannot extract IP: %w", err))
				return nil
			}
			ipApply = ipApply.WithAnnotations(map[string]string{
				OOBUnknownAnnotation: "",
			})
			err = r.Patch(ctx, ip, ssa.Apply(ipApply), client.FieldOwner(OOBFieldManager), client.ForceOwnership)
			if err != nil {
				log.Error(ctx, fmt.Errorf("cannot apply IP: %w", err))
				return nil
			}
		}
	}

	return reqs
}

func (r *OOBReconciler) enqueueOOBFromOOBSecret(ctx context.Context, secret *metalv1alpha1.OOBSecret) []reconcile.Request {
	var oobList metalv1alpha1.OOBList
	err := r.List(ctx, &oobList, client.MatchingFields{
		OOBSpecMACAddress: secret.Spec.MACAddress,
	})
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

func (r *OOBReconciler) enqueueOOBFromMachine(_ context.Context, machine *metalv1alpha1.Machine) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: machine.Spec.OOBRef.Name,
			},
		},
	}
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
		if m.access.Protocol.Name == "" {
			return nil, fmt.Errorf("prefix %s has no protocol name", m.Prefix)
		}
		if len(m.access.DefaultCredentials) == 0 {
			return nil, fmt.Errorf("prefix %s has no default credentials", m.Prefix)
		}
		for _, dc := range m.access.DefaultCredentials {
			if dc.Username == "" && dc.Password == "" {
				return nil, fmt.Errorf("prefix %s has invalid default credentials", m.Prefix)
			}
		}
		if m.access.Type == "" {
			return nil, fmt.Errorf("prefix %s has no type", m.Prefix)
		}

		db[m.Prefix] = m.access
	}

	return db, nil
}
