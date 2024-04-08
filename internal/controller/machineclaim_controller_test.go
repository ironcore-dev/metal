// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
)

var _ = Describe("MachineClaim Controller", func() {
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

	It("should claim a Machine by ref", func(ctx SpecContext) {
		By("Creating a Machine")
		machine := metalv1alpha1.Machine{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
			},
			Spec: metalv1alpha1.MachineSpec{
				UUID: uuid.NewString(),
				OOBRef: v1.LocalObjectReference{
					Name: "doesnotexist",
				},
			},
		}
		Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, &machine)

		By("Patching Machine state to Ready")
		Eventually(UpdateStatus(&machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a MachineClaim referencing the Machine")
		claim := metalv1alpha1.MachineClaim{
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
		Expect(k8sClient.Create(ctx, &claim)).To(Succeed())

		By("Expecting finalizer and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))

		By("Deleting the MachineClaim")
		Expect(k8sClient.Delete(ctx, &claim)).To(Succeed())

		By("Expecting machineclaimref and finalizer to be removed from the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Expecting MachineClaim to be removed")
		Eventually(Get(&claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should claim a Machine by selector", func(ctx SpecContext) {
		By("Creating a Machine")
		machine := metalv1alpha1.Machine{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Labels: map[string]string{
					"test": "test",
				},
			},
			Spec: metalv1alpha1.MachineSpec{
				UUID: uuid.NewString(),
				OOBRef: v1.LocalObjectReference{
					Name: "doesnotexist",
				},
			},
		}
		Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, &machine)

		By("Patching Machine state to Ready")
		Eventually(UpdateStatus(&machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a MachineClaim with a matching selector")
		claim := metalv1alpha1.MachineClaim{
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
		Expect(k8sClient.Create(ctx, &claim)).To(Succeed())

		By("Expecting finalizer, machineref, and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineRef.Name", Equal(machine.Name)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))

		By("Deleting the MachineClaim")
		Expect(k8sClient.Delete(ctx, &claim)).To(Succeed())

		By("Expecting machineclaimref and finalizer to be removed from the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Expecting MachineClaim to be removed")
		Eventually(Get(&claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should not claim a Machine with a wrong ref", func(ctx SpecContext) {
		By("Creating a MachineClaim referencing the Machine")
		claim := metalv1alpha1.MachineClaim{
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
		Expect(k8sClient.Create(ctx, &claim)).To(Succeed())

		By("Expecting finalizer and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Deleting the MachineClaim")
		Expect(k8sClient.Delete(ctx, &claim)).To(Succeed())

		By("Expecting MachineClaim to be removed")
		Eventually(Get(&claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should not claim a Machine with no matching selector", func(ctx SpecContext) {
		By("Creating a Machine")
		machine := metalv1alpha1.Machine{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Labels: map[string]string{
					"test": "test",
				},
			},
			Spec: metalv1alpha1.MachineSpec{
				UUID: uuid.NewString(),
				OOBRef: v1.LocalObjectReference{
					Name: "doesnotexist",
				},
			},
		}
		Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, &machine)

		By("Patching Machine state to Ready")
		Eventually(UpdateStatus(&machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a MachineClaim referencing the Machine")
		claim := metalv1alpha1.MachineClaim{
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
		Expect(k8sClient.Create(ctx, &claim)).To(Succeed())

		By("Expecting finalizer and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Expecting no finalizer or claimref on the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Deleting the MachineClaim")
		Expect(k8sClient.Delete(ctx, &claim)).To(Succeed())

		By("Expecting MachineClaim to be removed")
		Eventually(Get(&claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should claim a Machine by ref once the Machine becomes Ready", func(ctx SpecContext) {
		By("Creating a Machine")
		machine := metalv1alpha1.Machine{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
			},
			Spec: metalv1alpha1.MachineSpec{
				UUID: uuid.NewString(),
				OOBRef: v1.LocalObjectReference{
					Name: "doesnotexist",
				},
			},
		}
		Expect(k8sClient.Create(ctx, &machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, &machine)

		By("Patching Machine state to Error")
		Eventually(UpdateStatus(&machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateError
		})).Should(Succeed())

		By("Creating a MachineClaim referencing the Machine")
		claim := metalv1alpha1.MachineClaim{
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
		Expect(k8sClient.Create(ctx, &claim)).To(Succeed())
		DeferCleanup(k8sClient.Delete, &claim)

		By("Expecting finalizer and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Expecting no finalizer or claimref on the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Patching Machine state to Ready")
		Eventually(UpdateStatus(&machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Expecting finalizer and phase to be correct on the MachineClaim")
		Eventually(Object(&claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the Machine")
		Eventually(Object(&machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))
	})
})
