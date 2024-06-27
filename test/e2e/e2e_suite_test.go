// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/ironcore-dev/metal/internal/log"
	"github.com/ironcore-dev/metal/test/utils"
	logctrl "sigs.k8s.io/controller-runtime/pkg/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const macPrefix = "aabbcc"

var (
	interval = time.Second * 5
	timeout  = time.Second * 60
)

var (
	ctx  context.Context
	stop context.CancelFunc
	cmd  *exec.Cmd

	projectRoot string
)

var _ = BeforeSuite(func() {
	// This line prevents controller-runtime from complaining about log.SetLogger never being called
	ctx, stop = signal.NotifyContext(log.Setup(context.Background(), true, false, os.Stdout), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer stop()

	var err error
	projectRoot, err = utils.GetProjectRoot()
	Expect(err).NotTo(HaveOccurred())

	By("create kind cluster")
	cmd = exec.Command("make", "kind-create")
	cmd.Dir = projectRoot
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("build image for testing")
	cmd = exec.Command("make", "docker-build")
	cmd.Dir = projectRoot
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	// on this step metal-operator will be deployed with imagePullPolicy: Always,
	// hence it will pull published ghcr.io/ironcore-dev/metal:latest image which
	// does not contain changes.
	By("deploy metal")
	cmd = exec.Command("make", "deploy")
	cmd.Dir = projectRoot
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	// on this step newly built ghcr.io/ironcore-dev/metal:latest image will be
	// uploaded to testing kind cluster and will replace default image.
	By("upload metal docker image to kind cluster")
	cmd = exec.Command("make", "kind-load")
	cmd.Dir = projectRoot
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	// on this step deployment will be patched and imagePullPolicy will be set to
	// IfNotPresent hence metal-operator pod will use testing image.
	By("patching metal deployment")
	patchFile := filepath.Join(projectRoot, "test", "patch", "patch.yaml")
	cmd = exec.Command("kubectl", "patch", "--namespace",
		"metal-system", "deployment/metal-controller-manager",
		"--patch-file", patchFile)
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("wait while metal is ready after patching")
	cmd = exec.Command("kubectl", "wait", "--namespace",
		"metal-system", "deployment/metal-controller-manager",
		"--for", "jsonpath={.status.availableReplicas}=1", "--timeout=5m")
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("creating mac-db config map")
	cmFile := filepath.Join(projectRoot, "test", "samples", "macdb_configmap.yaml")
	cmd = exec.Command("kubectl", "apply", "-f", cmFile)
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("apply ipam CRD")
	ipamCRD := filepath.Join(projectRoot, "test", "ipam.metal.ironcore.dev_ips.yaml")
	cmd = exec.Command("kubectl", "apply", "-f", ipamCRD)
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	By("create oob namespace")
	cmd = exec.Command("kubectl", "create", "namespace", "oob")
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	logctrl.SetLogger(logr.FromContextOrDiscard(ctx))
})

var _ = AfterSuite(func() {
	var err error
	By("Delete kind environment")
	cmd = exec.Command("make", "kind-delete")
	cmd.Dir = projectRoot
	err = cmd.Run()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
})

// Run e2e tests using the Ginkgo runner.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "e2e suite")
}
