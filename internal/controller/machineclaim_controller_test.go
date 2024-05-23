// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
)

// nolint: dupl
var _ = Describe("MachineClaim Controller", Serial, func() {
	var ns *v1.Namespace

	BeforeEach(func(ctx SpecContext) {
		ns = &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
			},
		}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(k8sClient.Delete, ns)
	})

	Context("When reference defined", func() {
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
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)

			By("preparing inventory object")
			inventory = metalv1alpha1.Inventory{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-inventory-",
					Namespace:    ns.Name,
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
		})

		It("should claim a Machine", func(ctx SpecContext) {
			By("Creating a Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    ns.Name,
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
			Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)

			By("Patching Machine state to Ready")
			Eventually(UpdateStatus(&machine, func() {
				machine.Status.State = metalv1alpha1.MachineStateAvailable
			})).Should(Succeed())

			By("Creating a MachineClaim referencing the Machine")
			claim := &metalv1alpha1.MachineClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.MachineClaimSpec{
					MachineRef: &v1.LocalObjectReference{
						Name: machine.Name,
					},
					Image: "test",
					Power: metalv1alpha1.PowerOn,
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())

			By("Expecting finalizer and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseBound),
			))

			By("Expecting finalizer and machineclaimref to be correct on the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Spec.MachineClaimRef.Namespace", claim.Namespace),
				HaveField("Spec.MachineClaimRef.Name", claim.Name),
				HaveField("Spec.MachineClaimRef.UID", claim.UID),
			))

			By("Deleting the MachineClaim")
			Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

			By("Expecting machineclaimref and finalizer to be removed from the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
				HaveField("Spec.MachineClaimRef", BeNil()),
			))

			By("Expecting MachineClaim to be removed")
			Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
		})
	})

	Context("When selector defined", func() {
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
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)

			By("preparing inventory object")
			inventory = metalv1alpha1.Inventory{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-inventory-",
					Namespace:    ns.Name,
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
		})

		It("should claim a Machine", func(ctx SpecContext) {
			By("Creating a Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    ns.Name,
					GenerateName: "test-",
					Labels: map[string]string{
						"test": "test",
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
			Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)

			By("Patching Machine state to Ready")
			Eventually(UpdateStatus(&machine, func() {
				machine.Status.State = metalv1alpha1.MachineStateAvailable
			})).Should(Succeed())

			By("Creating a MachineClaim with a matching selector")
			claim := &metalv1alpha1.MachineClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.MachineClaimSpec{
					MachineSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"test": "test",
						},
					},
					Image: "test",
					Power: metalv1alpha1.PowerOn,
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())

			By("Expecting finalizer, machineref, and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Spec.MachineRef.Name", machine.Name),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseBound),
			))

			By("Expecting finalizer and machineclaimref to be correct on the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Spec.MachineClaimRef.Namespace", claim.Namespace),
				HaveField("Spec.MachineClaimRef.Name", claim.Name),
				HaveField("Spec.MachineClaimRef.UID", claim.UID),
			))

			By("Deleting the MachineClaim")
			Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

			By("Expecting machineclaimref and finalizer to be removed from the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
				HaveField("Spec.MachineClaimRef", BeNil()),
			))

			By("Expecting MachineClaim to be removed")
			Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
		})
	})

	Context("When wrong reference defined", func() {
		It("should not claim a Machine", func(ctx SpecContext) {
			By("Creating a MachineClaim referencing the Machine")
			claim := &metalv1alpha1.MachineClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.MachineClaimSpec{
					MachineRef: &v1.LocalObjectReference{
						Name: "doesnotexist",
					},
					Image: "test",
					Power: metalv1alpha1.PowerOn,
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())

			By("Expecting finalizer and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseUnbound),
			))

			By("Deleting the MachineClaim")
			Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

			By("Expecting MachineClaim to be removed")
			Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
		})
	})

	Context("When no matching selector defined", func() {
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
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)

			By("preparing inventory object")
			inventory = metalv1alpha1.Inventory{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-inventory-",
					Namespace:    ns.Name,
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
		})

		It("should not claim a Machine with no matching selector", func(ctx SpecContext) {
			By("Creating a Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    ns.Name,
					GenerateName: "test-",
					Labels: map[string]string{
						"test": "test",
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
			Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)

			By("Patching Machine state to Ready")
			Eventually(UpdateStatus(&machine, func() {
				machine.Status.State = metalv1alpha1.MachineStateAvailable
			})).Should(Succeed())

			By("Creating a MachineClaim referencing the Machine")
			claim := &metalv1alpha1.MachineClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.MachineClaimSpec{
					MachineSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"doesnotexist": "doesnotexist",
						},
					},
					Image: "test",
					Power: metalv1alpha1.PowerOn,
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())

			By("Expecting finalizer and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseUnbound),
			))

			By("Expecting no finalizer or claimref on the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
				HaveField("Spec.MachineClaimRef", BeNil()),
			))

			By("Deleting the MachineClaim")
			Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

			By("Expecting MachineClaim to be removed")
			Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
		})
	})

	Context("When Machine recovers from error", func() {
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
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.OOBSpec{
					MACAddress: "000000000001",
				},
			}
			Expect(k8sClient.Create(ctx, &oob)).Should(Succeed())
			Eventually(UpdateStatus(&oob, func() {
				oob.Status.Manufacturer = manufacturer
				oob.Status.SerialNumber = serialNumber
			})).Should(Succeed())
			DeferCleanup(k8sClient.Delete, &oob)

			By("preparing inventory object")
			inventory = metalv1alpha1.Inventory{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "sample-inventory-",
					Namespace:    ns.Name,
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
		})

		It("should claim a Machine by ref once the Machine becomes Available", func(ctx SpecContext) {
			By("Creating a Machine")
			machine = metalv1alpha1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    ns.Name,
					GenerateName: "test-",
					Annotations: map[string]string{
						MachineErrorAnnotation: "true",
					},
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
			Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
			DeferCleanup(k8sClient.Delete, &machine)

			Eventually(Object(&machine)).Should(HaveField("Status.State", Equal(metalv1alpha1.MachineStateError)))

			By("Creating a MachineClaim referencing the Machine")
			claim := &metalv1alpha1.MachineClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "test-",
					Namespace:    ns.Name,
				},
				Spec: metalv1alpha1.MachineClaimSpec{
					MachineRef: &v1.LocalObjectReference{
						Name: machine.Name,
					},
					Image: "test",
					Power: metalv1alpha1.PowerOn,
				},
			}
			Expect(k8sClient.Create(ctx, claim)).To(Succeed())
			DeferCleanup(func(ctx SpecContext) {
				Expect(k8sClient.Delete(ctx, claim)).To(Succeed())
				Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
			})

			By("Expecting finalizer and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseUnbound),
			))

			By("Expecting no finalizer or claimref on the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
				HaveField("Spec.MachineClaimRef", BeNil()),
			))

			By("Removing error annotation")
			Eventually(Update(&machine, func() {
				machine.Annotations = map[string]string{}
			})).Should(Succeed())
			Eventually(Object(&machine)).Should(HaveField("Status.State", Equal(metalv1alpha1.MachineStateTainted)))

			By("Removing cleanup flag")
			Eventually(Update(&machine, func() {
				machine.Spec.CleanupRequired = false
			})).Should(Succeed())

			By("Patching Machine state to Ready")
			Eventually(UpdateStatus(&machine, func() {
				machine.Status.State = metalv1alpha1.MachineStateAvailable
			})).Should(Succeed())

			By("Expecting finalizer and phase to be correct on the MachineClaim")
			Eventually(Object(claim)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Status.Phase", metalv1alpha1.MachineClaimPhaseBound),
			))

			By("Expecting finalizer and machineclaimref to be correct on the Machine")
			Eventually(Object(&machine)).Should(SatisfyAll(
				HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
				HaveField("Spec.MachineClaimRef.Namespace", claim.Namespace),
				HaveField("Spec.MachineClaimRef.Name", claim.Name),
				HaveField("Spec.MachineClaimRef.UID", claim.UID),
			))
		})
	})
})
