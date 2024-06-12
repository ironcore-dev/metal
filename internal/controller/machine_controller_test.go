// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"slices"

	"github.com/google/uuid"
	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"
)

// nolint: dupl
var _ = PDescribe("Machine Controller", Serial, func() {
	Context("when related resources not exist", func() {
		It("should fill conditions with status False", func(ctx SpecContext) {
			var idx int
			By("creating a new Machine")
			machine := metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
				Spec: metalv1alpha1.MachineSpec{
					UUID: uuid.NewString(),
					OOBRef: v1.LocalObjectReference{
						Name: "doesnotexist",
					},
					InventoryRef: &v1.LocalObjectReference{
						Name: "doesnotexist",
					},
				},
			}
			Expect(k8sClient.Create(ctx, &machine)).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(Object(&machine)).Should(Succeed())
				g.Expect(machine).Should(HaveField("Status.State", Equal("Initial")))
				idx = slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInitializedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInitializedConditionNegReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInitializedConditionNegMessage))

				idx = slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInventoriedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInventoriedConditionNegReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInventoriedConditionNegMessage))

				idx = slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineClassifiedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineClassifiedConditionNegReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineClassifiedConditionNegMessage))

				idx = slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineReadyConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionFalse))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineReadyConditionNegReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineReadyConditionNegMessage))
			})
		})
	})

	Context("when related oob object exist", func() {
		var (
			oob     metalv1alpha1.OOB
			machine metalv1alpha1.Machine
		)
		JustBeforeEach(func(ctx SpecContext) {
			By("preparing oob object")
			oob = metalv1alpha1.OOB{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-oob-",
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())

			By("creating a new Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
				},
				Spec: metalv1alpha1.MachineSpec{
					UUID: uuid.NewString(),
					OOBRef: v1.LocalObjectReference{
						Name: oob.GetName(),
					},
					InventoryRef: &v1.LocalObjectReference{
						Name: "doesnotexist",
					},
				},
			}
			Expect(k8sClient.Create(ctx, &machine)).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)
		})

		It("should fulfill status from oob", func() {
			Eventually(func(g Gomega) {
				g.Expect(Object(&machine)).Should(Succeed())
				g.Expect(machine).Should(HaveField("Status.State", Equal("Initial")))
				idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInitializedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionTrue))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInitializedConditionPosReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInitializedConditionPosMessage))
			})
		})
	})

	Context("when related inventory object exist", func() {
		var (
			oob       metalv1alpha1.OOB
			inventory metalv1alpha1.Inventory
			machine   metalv1alpha1.Machine
		)

		JustBeforeEach(func(ctx SpecContext) {
			By("preparing oob object")
			oob = metalv1alpha1.OOB{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-oob-",
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())

			By("preparing inventory object")
			inventory = metalv1alpha1.Inventory{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-inventory-",
				},
				Spec: metalv1alpha1.InventorySpec{
					System: &metalv1alpha1.SystemSpec{
						ID:           uuid.NewString(),
						Manufacturer: manufacturer,
						ProductSKU:   "1",
						SerialNumber: serialNumber,
					},
					Blocks: make([]metalv1alpha1.BlockSpec, 0),
					Memory: &metalv1alpha1.MemorySpec{Total: uint64(1)},
					CPUs:   make([]metalv1alpha1.CPUSpec, 0),
					Host:   &metalv1alpha1.HostSpec{Name: "sample-host"},
					NICs: []metalv1alpha1.NICSpec{
						{
							Name:       "eth0",
							MACAddress: "00:00:00:00:01:01",
						},
						{
							Name:       "eth1",
							MACAddress: "00:00:00:00:01:02",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, &inventory)).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &inventory)

			By("creating a new Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Labels: map[string]string{
						fmt.Sprintf("%s%s", MachineSizeLabelPrefix, "m5large"): "true",
					},
				},
				Spec: metalv1alpha1.MachineSpec{
					UUID: uuid.NewString(),
					OOBRef: v1.LocalObjectReference{
						Name: oob.GetName(),
					},
					InventoryRef: &v1.LocalObjectReference{
						Name: inventory.GetName(),
					},
				},
			}
			Expect(k8sClient.Create(ctx, &machine)).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)
		})

		It("should fill status from inventory", func(ctx SpecContext) {
			Eventually(func(g Gomega) {
				g.Expect(Object(&machine)).Should(Succeed())
				g.Expect(machine).Should(HaveField("Status.State", Equal(metalv1alpha1.MachineStateAvailable)))
				idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInventoriedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionTrue))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInventoriedConditionPosReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInventoriedConditionPosMessage))
				g.Expect(len(machine.Status.NetworkInterfaces)).Should(Equal(2))
			})
		})

		It("should update network interfaces from inventory", func(ctx SpecContext) {
			Eventually(func(g Gomega) {
				g.Expect(Object(&machine)).Should(Succeed())
				g.Expect(machine).Should(HaveField("Status.State", Equal(metalv1alpha1.MachineStateAvailable)))
				idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInventoriedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionTrue))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInventoriedConditionPosReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInventoriedConditionPosMessage))
				g.Expect(len(machine.Status.NetworkInterfaces)).Should(Equal(2))
			})

			By("updating inventory object")
			Eventually(UpdateStatus(&inventory, func() {
				inventory.Spec.NICs = []metalv1alpha1.NICSpec{
					{
						Name:       "eth3",
						MACAddress: "00:00:00:00:01:03",
					},
				}
			})).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(Object(&machine)).Should(Succeed())
				g.Expect(machine).Should(HaveField("Status.State", Equal(metalv1alpha1.MachineStateAvailable)))
				idx := slices.IndexFunc(machine.Status.Conditions, func(c metav1.Condition) bool {
					return c.Type == MachineInventoriedConditionType
				})
				g.Expect(machine.Status.Conditions[idx].Status).Should(Equal(metav1.ConditionTrue))
				g.Expect(machine.Status.Conditions[idx].Reason).Should(Equal(MachineInventoriedConditionPosReason))
				g.Expect(machine.Status.Conditions[idx].Message).Should(Equal(MachineInventoriedConditionPosMessage))
				g.Expect(len(machine.Status.NetworkInterfaces)).Should(Equal(1))
			})
		})
	})
})
