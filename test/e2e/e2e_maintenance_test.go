// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"fmt"
	"os/exec"
	"path/filepath"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	"github.com/ironcore-dev/metal/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var _ = Describe("metal-operator", Ordered, func() {
	var (
		mac, ip, ipFile string
		output          []byte
		machines        *metalv1alpha1.MachineList

		err error
	)

	BeforeAll(func() {
		mac, err = utils.GenerateMacAddress(macPrefix)
		Expect(err).NotTo(HaveOccurred())
		ip, err = utils.GenerateIpAddressString()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		By("cleanup ip")
		cmd = exec.Command("kubectl", "delete", "ip", "--all", "-A")
		err = cmd.Run()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("cleanup machine claims")
		cmd = exec.Command("kubectl", "delete", "machineclaim", "--all", "-A")
		err = cmd.Run()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("cleanup oob")
		cmd = exec.Command("kubectl", "delete", "oob", "--all")
		err = cmd.Run()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())

		By("cleanup machines")
		cmd = exec.Command("kubectl", "delete", "oob", "--all")
		err = cmd.Run()
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	})

	Context("when machine is being reconciled", func() {
		var (
			machineName        string
			machine            *metalv1alpha1.Machine
			machineTargetState metalv1alpha1.MachineState
		)
		It("it should be in Available state when all conditions met", func() {
			ipFile = filepath.Join(projectRoot, "test", "samples", "oob_ip.yaml")
			By("create a new oob ip address")
			cmd = exec.Command("kubectl", "apply", "-f", ipFile)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("patch ip status")
			patch := fmt.Sprintf("{\"status\": {\"reserved\": \"%s\", \"state\": \"Finished\"}}", ip)
			cmd = exec.Command("kubectl", "patch", "-f", ipFile, "--type=merge",
				"--subresource", "status", "--patch", patch)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("set label on ip")
			label := fmt.Sprintf("mac=%s", mac)
			cmd = exec.Command("kubectl", "label", "-f", ipFile, label)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("wait for oob")
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "oobs.metal.ironcore.dev", mac)
				err = cmd.Run()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
			}, timeout, interval).Should(Succeed())

			By("verify oob condition Ready has status True")
			Eventually(func(g Gomega) {
				oob := &metalv1alpha1.OOB{}
				cmd = exec.Command("kubectl", "get", "oobs.metal.ironcore.dev", mac, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, oob)).To(Succeed())
				g.Expect(oob.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
			}, timeout, interval).Should(Succeed())

			machines = &metalv1alpha1.MachineList{}
			cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", "-oyaml")
			output, err = cmd.CombinedOutput()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			Expect(yaml.Unmarshal(output, machines)).To(Succeed())
			machine = machines.Items[0].DeepCopy()
			machineName = machine.Name

			By("patch boot configuration state")
			Eventually(func(g Gomega) {
				patch := "{\"status\": {\"state\": \"Ready\"}}"
				cmd = exec.Command("kubectl", "patch", "bootconfiguration", machineName, "--type=merge",
					"--subresource", "status", "--patch", patch)
				err = cmd.Run()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
			}, timeout, interval).Should(Succeed())

			By("create inventory")
			input := fmt.Sprintf("apiVersion: metal.ironcore.dev/v1alpha1\nkind: Inventory\nmetadata:\n  name: %s\nspec:\n  system:\n    id: %s\n    manufacturer: \"Fake\"\n    productSku: \"1\"\n    serialNumber: \"1\"\n  blocks: []\n  memory:\n    total: 8\n  cpus: []\n  host:\n    name: \"fake\"\n  nics: []",
				machine.Spec.UUID, machine.Spec.UUID)
			cmd1 := exec.Command("echo", input)
			cmd2 := exec.Command("kubectl", "apply", "-f", "-")
			cmd2.Stdin, err = cmd1.StdoutPipe()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			err = cmd2.Start()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			err = cmd1.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			err = cmd2.Wait()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("create size")
			sizeFile := filepath.Join(projectRoot, "test", "samples", "size.yaml")
			cmd = exec.Command("kubectl", "apply", "-f", sizeFile)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Available")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(metalv1alpha1.MachineStateAvailable))
			}, timeout, interval).Should(Succeed())
			machineTargetState = machine.Status.State
		})

		It("it should be in Maintenance state when corresponding flag is set", func() {
			By("patch machine spec.maintenance")
			patch := "{\"spec\": {\"maintenance\": true}}"
			cmd = exec.Command("kubectl", "patch", "machines.metal.ironcore.dev", machineName, "--type=merge",
				"--patch", patch)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Maintenance")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(metalv1alpha1.MachineStateMaintenance))
			})
		})

		It("it should get previous state when maintenance flag is set to false", func() {
			By("patch machine spec.maintenance")
			patch := "{\"spec\": {\"maintenance\": false}}"
			cmd = exec.Command("kubectl", "patch", "machines.metal.ironcore.dev", machineName, "--type=merge",
				"--patch", patch)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Available")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(machineTargetState))
			})
		})

		It("it should be in Reserved state and get power state according to claim definition when machine claim created", func() {
			By("create claim with power on")
			claimFile := filepath.Join(projectRoot, "test", "samples", "claim_power_on.yaml")
			cmd = exec.Command("kubectl", "apply", "-f", claimFile)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Reserved and powered on")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(metalv1alpha1.MachineStateReserved))
				g.Expect(machine.Status.Power).To(Equal(metalv1alpha1.PowerOn))
			}, timeout, interval).Should(Succeed())
			machineTargetState = machine.Status.State
		})

		It("it should be in Maintenance state when corresponding flag is set", func() {
			By("patch machine spec.maintenance")
			patch := "{\"spec\": {\"maintenance\": true}}"
			cmd = exec.Command("kubectl", "patch", "machines.metal.ironcore.dev", machineName, "--type=merge",
				"--patch", patch)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Maintenance")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(metalv1alpha1.MachineStateMaintenance))
			})
		})

		It("it should get previous state when maintenance flag is set to false", func() {
			By("patch machine spec.maintenance")
			patch := "{\"spec\": {\"maintenance\": false}}"
			cmd = exec.Command("kubectl", "patch", "machines.metal.ironcore.dev", machineName, "--type=merge",
				"--patch", patch)
			err = cmd.Run()
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("verify machine has state Reserved")
			machine = &metalv1alpha1.Machine{}
			Eventually(func(g Gomega) {
				cmd = exec.Command("kubectl", "get", "machines.metal.ironcore.dev", machineName, "-oyaml")
				output, err = cmd.CombinedOutput()
				g.ExpectWithOffset(1, err).NotTo(HaveOccurred())
				g.Expect(yaml.Unmarshal(output, machine)).To(Succeed())
				g.Expect(machine.Status.State).To(Equal(machineTargetState))
			})
		})
	})
})
