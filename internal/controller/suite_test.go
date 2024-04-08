// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/log"
	//+kubebuilder:scaffold:imports
)

var (
	k8sClient client.Client
)

func TestControllers(t *testing.T) {
	SetDefaultEventuallyTimeout(3 * time.Second)
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller")
}

var _ = BeforeSuite(func() {
	path, err := exec.Command("go", "run", "sigs.k8s.io/controller-runtime/tools/setup-envtest", "use", "-p=path").Output()
	Expect(err).NotTo(HaveOccurred())
	Expect(os.Setenv("KUBEBUILDER_ASSETS", string(path))).To(Succeed())

	ctx, cancel := context.WithCancel(log.Setup(context.Background(), true, false, GinkgoWriter))
	DeferCleanup(cancel)
	l := logr.FromContextOrDiscard(ctx)
	klog.SetLogger(l)
	ctrl.SetLogger(l)

	scheme := runtime.NewScheme()
	Expect(kscheme.AddToScheme(scheme)).To(Succeed())
	Expect(metalv1alpha1.AddToScheme(scheme)).To(Succeed())
	//+kubebuilder:scaffold:scheme

	testEnv := &envtest.Environment{
		ErrorIfCRDPathMissing: true,
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
		},
	}
	var cfg *rest.Config
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())
	DeferCleanup(testEnv.Stop)

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
	SetClient(k8sClient)

	ns := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "system-",
		},
	}
	Expect(k8sClient.Create(ctx, &ns)).To(Succeed())
	DeferCleanup(k8sClient.Delete, &ns)

	var mgr manager.Manager
	mgr, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: "0",
		},
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(mgr).NotTo(BeNil())
	Expect(CreateIndexes(ctx, mgr)).To(Succeed())

	var machineReconciler *MachineReconciler
	machineReconciler, err = NewMachineReconciler()
	Expect(err).NotTo(HaveOccurred())
	Expect(machineReconciler).NotTo(BeNil())
	Expect(machineReconciler.SetupWithManager(mgr)).To(Succeed())

	var machineClaimReconciler *MachineClaimReconciler
	machineClaimReconciler, err = NewMachineClaimReconciler()
	Expect(err).NotTo(HaveOccurred())
	Expect(machineClaimReconciler).NotTo(BeNil())
	Expect(machineClaimReconciler.SetupWithManager(mgr)).To(Succeed())

	var oobReconciler *OOBReconciler
	oobReconciler, err = NewOOBReconciler()
	Expect(err).NotTo(HaveOccurred())
	Expect(oobReconciler).NotTo(BeNil())
	Expect(oobReconciler.SetupWithManager(mgr)).To(Succeed())

	var oobSecretReconciler *OOBSecretReconciler
	oobSecretReconciler, err = NewOOBSecretReconciler()
	Expect(err).NotTo(HaveOccurred())
	Expect(oobSecretReconciler).NotTo(BeNil())
	Expect(oobSecretReconciler.SetupWithManager(mgr)).To(Succeed())

	mgrCtx, mgrCancel := context.WithCancel(ctx)
	DeferCleanup(mgrCancel)

	go func() {
		defer GinkgoRecover()

		Expect(mgr.Start(mgrCtx)).To(Succeed())
	}()
})
