// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"

	ipamv1alpha1 "github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	. "sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	metalv1alpha1 "github.com/ironcore-dev/metal/api/v1alpha1"
	"github.com/ironcore-dev/metal/internal/ssa"
)

var _ = Describe("OOB Controller", func() {
	It("should create an OOB from an IP", func(ctx SpecContext) {
		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddeeff",
					"test":        "test",
				},
			},
		}
		Expect(k8sClient.Create(ctx, ip)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
			Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))
		})

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aabbccddeeff",
			},
		}
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", "aabbccddeeff"),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))

		By("Expecting finalizer to be correct on the IP")
		Eventually(Object(ip)).Should(HaveField("Finalizers", ContainElement(OOBFinalizer)))

		By("Deleting the OOB")
		Expect(k8sClient.Delete(ctx, oob)).To(Succeed())

		By("Expecting OOB to be deleted")
		Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))

		By("Expecting finalizer to be cleared on the IP")
		Eventually(Object(ip)).Should(HaveField("Finalizers", Not(ContainElement(OOBFinalizer))))
	})

	It("should set the OOB to ignored if the ignore annotation is set", func(ctx SpecContext) {
		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddeeff",
					"test":        "test",
				},
			},
		}
		Expect(k8sClient.Create(ctx, ip)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
			Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))
		})

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aabbccddeeff",
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
		})

		By("Setting an ignore annoation on the OOB")
		Eventually(Update(oob, func() {
			if oob.Annotations == nil {
				oob.Annotations = make(map[string]string, 1)
			}
			oob.Annotations[OOBIgnoreAnnotation] = ""
		})).Should(Succeed())

		By("Expecting OOB to be ignored")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateIgnored),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonIgnored)),
		))

		By("Clearing the ignore annoation on the OOB")
		Eventually(Update(oob, func() {
			delete(oob.Annotations, OOBIgnoreAnnotation)
		})).Should(Succeed())

		By("Expecting OOB not to be ignored")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))
	})

	It("should handle an unavailable endpoint", func(ctx SpecContext) {
		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddeeff",
					"test":        "test",
				},
			},
		}
		Expect(k8sClient.Create(ctx, ip)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
			Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))
		})

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aabbccddeeff",
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
		})

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", "aabbccddeeff"),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))

		By("Deleting the IP")
		Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
		Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))

		By("Expecting the OOB to have no endpoint")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.EndpointRef", BeNil()),
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonNoEndpoint)),
		))

		By("Recreating the IP")
		ip = &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ip.Name,
				Namespace: OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddeeff",
					"test":        "test",
				},
			},
		}
		Expect(k8sClient.Create(ctx, ip)).To(Succeed())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have an endpoint")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))
	})

	It("should handle a bad endpoint", func(ctx SpecContext) {
		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddeeff",
					"test":        "test",
				},
			},
		}
		Expect(k8sClient.Create(ctx, ip)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
			Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))
		})

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aabbccddeeff",
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
		})

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", "aabbccddeeff"),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))

		By("Setting an incorrect MAC on the IP")
		Eventually(Update(ip, func() {
			ip.Labels[OOBIPMacLabel] = "xxxxxxyyyyyy"
		})).Should(Succeed())

		By("Expecting the OOB to be in an error state")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateError),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonError)),
		))

		By("Restoring the MAC on the IP")
		Eventually(Update(ip, func() {
			ip.Labels[OOBIPMacLabel] = "aabbccddeeff"
		})).Should(Succeed())

		By("Expecting the OOB to recover")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))

		By("Setting a failed state on the IP")
		Eventually(UpdateStatus(ip, func() {
			ip.Status.State = ipamv1alpha1.CFailedIPState
		})).Should(Succeed())

		By("Expecting the OOB to be in an error state")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateError),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonError)),
		))

		By("Restoring the state on the IP")
		Eventually(UpdateStatus(ip, func() {
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to recover")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateUnready),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonInProgress)),
		))
	})
})

func readyReason(o client.Object) (string, error) {
	oob, ok := o.(*metalv1alpha1.OOB)
	if !ok {
		return "", fmt.Errorf("%s is not an OOB", o.GetName())
	}
	var cond metav1.Condition
	cond, ok = ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if !ok {
		return "", fmt.Errorf("%s has no condition of type %s", oob.Name, metalv1alpha1.OOBConditionTypeReady)
	}
	return cond.Reason, nil
}
