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

var _ = Describe("OOB Controller", Serial, func() {
	mac := "aabbccddeeff"

	It("should create an OOB from an IP", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Expecting finalizer to be correct on the IP")
		Eventually(Object(ip)).Should(HaveField("Finalizers", ContainElement(OOBFinalizer)))
	})

	It("should set the OOB to ignored if the ignore annotation is set", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should handle an unavailable endpoint", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Deleting the IP")
		Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
		Eventually(Get(ip)).Should(Satisfy(errors.IsNotFound))

		By("Expecting the OOB to have no endpoint")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.EndpointRef", BeNil()),
			HaveField("Status.State", metalv1alpha1.OOBStateNoEndpoint),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonNoEndpoint)),
		))

		By("Recreating the IP")
		ip = &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ip.Name,
				Namespace: OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should handle a bad endpoint", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.EndpointRef.Name", ip.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Setting an incorrect MAC on the IP")
		Eventually(Update(ip, func() {
			ip.Labels[OOBIPMacLabel] = "000000000000"
		})).Should(Succeed())

		By("Expecting the OOB to be in an error state")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateError),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonError)),
			WithTransform(readyMessage, HavePrefix(OOBErrorBadEndpoint+": ")),
		))

		By("Restoring the MAC on the IP")
		Eventually(Update(ip, func() {
			ip.Labels[OOBIPMacLabel] = oob.Name
		})).Should(Succeed())

		By("Expecting the OOB to recover")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Setting a failed state on the IP")
		Eventually(UpdateStatus(ip, func() {
			ip.Status.State = ipamv1alpha1.CFailedIPState
		})).Should(Succeed())

		By("Expecting the OOB to be in an error state")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateError),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonError)),
			WithTransform(readyMessage, HavePrefix(OOBErrorBadEndpoint+": ")),
		))

		By("Restoring the state on the IP")
		Eventually(UpdateStatus(ip, func() {
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to recover")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should create a new credentials secret", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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

		By("Expecting a correct OOBSecret to have been created")
		Eventually(Object(secret)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.Username", HavePrefix("metal-")),
			HaveField("Spec.Password", Not(BeEmpty())),
			HaveField("Spec.ExpirationTime", Not(BeNil())),
		))
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.SecretRef.Name", secret.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should not create an OOB if the MAC is unknown", func(ctx SpecContext) {
		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: "aabbccddee00",
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

		By("Expecting the IP to have an unknown annotation")
		Eventually(Object(ip)).Should(HaveField("Annotations", HaveKey(OOBUnknownAnnotation)))

		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aabbccddee00",
			},
		}

		By("Expecting OOB not to exist")
		Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
	})

	It("should handle a bad credentials secret", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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

		By("Expecting a correct OOBSecret to have been created")
		Eventually(Object(secret)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.Username", HavePrefix("metal-")),
			HaveField("Spec.Password", Not(BeEmpty())),
			HaveField("Spec.ExpirationTime", Not(BeNil())),
		))
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.SecretRef.Name", secret.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Setting an incorrect MAC on the OOBSecret")
		Eventually(Update(secret, func() {
			secret.Spec.MACAddress = "000000000000"
		})).Should(Succeed())

		By("Expecting the OOB to be in an error state")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateError),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonError)),
			WithTransform(readyMessage, HavePrefix(OOBErrorBadCredentials+": ")),
		))

		By("Restoring the MAC on the OOBSecret")
		Eventually(Update(secret, func() {
			secret.Spec.MACAddress = mac
		})).Should(Succeed())

		By("Expecting the OOB to recover")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should rotate expiring credentials", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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

		By("Expecting a correct OOBSecret to have been created")
		Eventually(Object(secret)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.Username", HavePrefix("metal-")),
			HaveField("Spec.Password", Not(BeEmpty())),
			HaveField("Spec.ExpirationTime", Not(BeNil())),
		))
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.SecretRef.Name", secret.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		var obj client.Object
		obj, err = Object(secret)()
		Expect(err).NotTo(HaveOccurred())
		secret = obj.(*metalv1alpha1.OOBSecret)
		Expect(secret).NotTo(BeNil())
		username, password, expiration := secret.Spec.Username, secret.Spec.Password, metav1.Now()

		By("Setting the expiration date of the OOBSecret to now")
		Eventually(Update(secret, func() {
			secret.Spec.ExpirationTime = &expiration
		})).Should(Succeed())

		By("Expecting the OOBSecret to contain new credentials")
		Eventually(Object(secret)).Should(SatisfyAll(
			HaveField("Finalizers", ContainElement(OOBFinalizer)),
			HaveField("Spec.MACAddress", mac),
			HaveField("Spec.Username", Not(Equal(username))),
			HaveField("Spec.Password", Not(Equal(password))),
			HaveField("Spec.ExpirationTime", Not(Equal(expiration))),
		))
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Spec.SecretRef.Name", secret.Name),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should retrieve BMC info", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.Manufacturer", "Fake"),
			HaveField("Status.SerialNumber", "0"),
			HaveField("Status.FirmwareVersion", "1"),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))
	})

	It("should create Machine objects", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		secret := &metalv1alpha1.OOBSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}
		machine := &metalv1alpha1.Machine{}
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, oob)).To(Succeed())
			Eventually(Get(oob)).Should(Satisfy(errors.IsNotFound))
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
			Eventually(Get(secret)).Should(Satisfy(errors.IsNotFound))
			Eventually(Get(machine)).Should(Satisfy(errors.IsNotFound))
		})

		By("Creating an IP")
		ip := &ipamv1alpha1.IP{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-",
				Namespace:    OOBTemporaryNamespaceHack,
				Labels: map[string]string{
					OOBIPMacLabel: mac,
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

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob)).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Listing machines")
		machines := &metalv1alpha1.MachineList{}
		Eventually(ObjectList(machines)).Should(HaveField("Items", HaveLen(1)))
		machine = &machines.Items[0]

		By("Expecting Machine to have the correct data")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Spec.UUID", machine.Name),
			HaveField("Spec.OOBRef.Name", oob.Name),
			HaveField("Status.Manufacturer", "Fake"),
			HaveField("Status.SKU", "Fake-0"),
			HaveField("Status.SerialNumber", "1"),
			HaveField("Status.Power", metalv1alpha1.PowerOn),
			HaveField("Status.LocatorLED", metalv1alpha1.LEDOff),
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

func readyMessage(o client.Object) (string, error) {
	oob, ok := o.(*metalv1alpha1.OOB)
	if !ok {
		return "", fmt.Errorf("%s is not an OOB", o.GetName())
	}
	var cond metav1.Condition
	cond, ok = ssa.GetCondition(oob.Status.Conditions, metalv1alpha1.OOBConditionTypeReady)
	if !ok {
		return "", fmt.Errorf("%s has no condition of type %s", oob.Name, metalv1alpha1.OOBConditionTypeReady)
	}
	return cond.Message, nil
}
