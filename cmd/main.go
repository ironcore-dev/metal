// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/controller"
	"github.com/ironcore-dev/metal/internal/log"
	//+kubebuilder:scaffold:imports
)

type params struct {
	dev                          bool
	leaderElection               bool
	healthProbeBindAddress       string
	metricsBindAddress           string
	secureMetrics                bool
	enableHTTP2                  bool
	kubeconfig                   string
	enableMachineController      bool
	enableMachineClaimController bool
	enableOOBController          bool
	enableOOBSecretController    bool
}

func parseCmdLine() params {
	pflag.Usage = usage
	pflag.ErrHelp = nil
	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	pflag.Bool("dev", false, "Log human-readable messages at debug level.")
	pflag.Bool("leader-elect", false, "Enable leader election to ensure there is only one active controller manager.")
	pflag.String("health-probe-bind-address", "", "The address that the health probe server binds to.")
	pflag.String("metrics-bind-address", "0", "The address that the metrics server binds to.")
	pflag.Bool("metrics-secure", false, "Serve metrics securely.")
	pflag.Bool("enable-http2", false, "Enable HTTP2 for the metrics and webhook servers.")
	pflag.String("kubeconfig", "", "Use a kubeconfig to run out of cluster.")
	pflag.Bool("enable-machine-controller", true, "Enable the Machine controller.")
	pflag.Bool("enable-machineclaim-controller", true, "Enable the MachineClaim controller.")
	pflag.Bool("enable-oob-controller", true, "Enable the OOB controller.")
	pflag.Bool("enable-oobsecret-controller", true, "Enable the OOBSecret controller.")

	var help bool
	pflag.BoolVarP(&help, "help", "h", false, "Show this help message.")
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		exitUsage(err)
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	err = pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		exitUsage(err)
	}
	if help {
		exitUsage(nil)
	}

	return params{
		dev:                          viper.GetBool("dev"),
		leaderElection:               viper.GetBool("leader-elect"),
		healthProbeBindAddress:       viper.GetString("health-probe-bind-address"),
		metricsBindAddress:           viper.GetString("metrics-bind-address"),
		secureMetrics:                viper.GetBool("metrics-secure"),
		enableHTTP2:                  viper.GetBool("enable-http2"),
		kubeconfig:                   viper.GetString("kubeconfig"),
		enableMachineController:      viper.GetBool("enable-machine-controller"),
		enableMachineClaimController: viper.GetBool("enable-machineclaim-controller"),
		enableOOBController:          viper.GetBool("enable-oob-controller"),
		enableOOBSecretController:    viper.GetBool("enable-oobsecret-controller"),
	}
}

func usage() {
	name := filepath.Base(os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--option]...\n", name)
	_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
	pflag.PrintDefaults()
}

func exitUsage(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", filepath.Base(os.Args[0]), err)
	}
	pflag.Usage()
	os.Exit(2)
}

func main() {
	p := parseCmdLine()

	var exitCode int
	defer func() {
		os.Exit(exitCode)
	}()

	ctx, stop := signal.NotifyContext(log.Setup(context.Background(), p.dev, false, os.Stderr), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer stop()
	log.Info(ctx, "Starting OOB operator")

	defer func() {
		log.Info(ctx, "Exiting", "exitCode", exitCode)
	}()

	l := logr.FromContextOrDiscard(ctx)
	klog.SetLogger(l)
	ctrl.SetLogger(l)

	scheme := runtime.NewScheme()
	err := kscheme.AddToScheme(scheme)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create type scheme: %w", err))
		exitCode = 1
		return
	}
	err = metalv1alpha1.AddToScheme(scheme)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create type scheme: %w", err))
		exitCode = 1
		return
	}
	//+kubebuilder:scaffold:scheme

	var kcfg *rest.Config
	kcfg, err = ctrl.GetConfig()
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot get kubeconfig: %w", err))
		exitCode = 1
		return
	}

	var tlsOpts []func(*tls.Config)
	if !p.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		})
	}

	var mgr manager.Manager
	mgr, err = ctrl.NewManager(kcfg, ctrl.Options{
		Scheme:           scheme,
		LeaderElection:   p.leaderElection,
		LeaderElectionID: "metal.ironcore.dev",
		Metrics: server.Options{
			BindAddress:   p.metricsBindAddress,
			SecureServing: p.secureMetrics,
			TLSOpts:       tlsOpts,
		},
		HealthProbeBindAddress: p.healthProbeBindAddress,
		WebhookServer: webhook.NewServer(webhook.Options{
			TLSOpts: tlsOpts,
		}),
		BaseContext: func() context.Context {
			return ctx
		},
	})
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create manager: %w", err))
		exitCode = 1
		return
	}

	err = controller.NewMachineReconciler().SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "Machine")
		exitCode = 1
		return
	}
	err = controller.NewMachineClaimReconciler().SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "MachineClaim")
		exitCode = 1
		return
	}
	err = controller.NewOOBReconciler().SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "OOB")
		exitCode = 1
		return
	}
	err = controller.NewOOBSecretReconciler().SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "OOBSecret")
		exitCode = 1
		return
	}
	//+kubebuilder:scaffold:builder

	err = mgr.AddHealthzCheck("health", healthz.Ping)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot set up health check: %w", err))
		exitCode = 1
		return
	}

	err = mgr.AddReadyzCheck("check", healthz.Ping)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot set up ready check: %w", err))
		exitCode = 1
		return
	}

	log.Info(ctx, "Starting manager")
	err = mgr.Start(ctx)
	if err != nil {
		log.Error(ctx, err)
		exitCode = 1
		return
	}
}
