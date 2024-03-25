/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	It("should claim a machine by ref", func(ctx SpecContext) {
		By("Creating a machine")
		machine := &metalv1alpha1.Machine{
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
		Expect(k8sClient.Create(ctx, machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, machine)

		By("Patching machine state to Ready")
		Eventually(UpdateStatus(machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a machineclaim referencing the machine")
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

		By("Expecting finalizer and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))

		By("Deleting the claim")
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		By("Expecting machineclaimref and finalizer to be removed from the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Expecting machineclaim to be removed")
		Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should claim a machine by selector", func(ctx SpecContext) {
		By("Creating a machine")
		machine := &metalv1alpha1.Machine{
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
		Expect(k8sClient.Create(ctx, machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, machine)

		By("Patching machine state to Ready")
		Eventually(UpdateStatus(machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a machineclaim with a matching selector")
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

		By("Expecting finalizer, machineref, and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineRef.Name", Equal(machine.Name)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))

		By("Deleting the machineclaim")
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		By("Expecting machineclaimref and finalizer to be removed from the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Expecting machineclaim to be removed")
		Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should not claim a machine with a wrong ref", func(ctx SpecContext) {
		By("Creating a machineclaim referencing the machine")
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

		By("Expecting finalizer and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Deleting the machineclaim")
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		By("Expecting machineclaim to be removed")
		Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should not claim a machine with no matching selector", func(ctx SpecContext) {
		By("Creating a machine")
		machine := &metalv1alpha1.Machine{
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
		Expect(k8sClient.Create(ctx, machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, machine)

		By("Patching machine state to Ready")
		Eventually(UpdateStatus(machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Creating a machineclaim referencing the machine")
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

		By("Expecting finalizer and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Expecting no finalizer or claimref on the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Deleting the machineclaim")
		Expect(k8sClient.Delete(ctx, claim)).To(Succeed())

		By("Expecting machineclaim to be removed")
		Eventually(Get(claim)).Should(Satisfy(errors.IsNotFound))
	})

	It("should claim a machine by ref once the machine becomes Ready", func(ctx SpecContext) {
		By("Creating a machine")
		machine := &metalv1alpha1.Machine{
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
		Expect(k8sClient.Create(ctx, machine)).To(Succeed())
		DeferCleanup(k8sClient.Delete, machine)

		By("Patching machine state to Error")
		Eventually(UpdateStatus(machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateError
		})).Should(Succeed())

		By("Creating a machineclaim referencing the machine")
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
		DeferCleanup(k8sClient.Delete, claim)

		By("Expecting finalizer and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseUnbound)),
		))

		By("Expecting no finalizer or claimref on the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", Not(ContainElement(MachineClaimFinalizer))),
			HaveField("Spec.MachineClaimRef", BeNil()),
		))

		By("Waiting for reconciliation to finish")
		// TODO: time.Sleep(1 * time.Second)

		By("Patching machine state to Ready")
		Eventually(UpdateStatus(machine, func() {
			machine.Status.State = metalv1alpha1.MachineStateReady
		})).Should(Succeed())

		By("Expecting finalizer and phase to be correct on the machineclaim")
		Eventually(Object(claim)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Status.Phase", Equal(metalv1alpha1.MachineClaimPhaseBound)),
		))

		By("Expecting finalizer and machineclaimref to be correct on the machine")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(MachineClaimFinalizer)),
			HaveField("Spec.MachineClaimRef.Namespace", Equal(claim.Namespace)),
			HaveField("Spec.MachineClaimRef.Name", Equal(claim.Name)),
			HaveField("Spec.MachineClaimRef.UID", Equal(claim.UID)),
		))
	})
})
