// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"time"

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
	timeToReady := time.Second * 3
	shutdownTimeout := time.Second * 1

	BeforeEach(func(ctx SpecContext) {
		Eventually(ObjectList(&ipamv1alpha1.IPList{}, &client.ListOptions{
			Namespace: OOBTemporaryNamespaceHack,
		})).Should(HaveField("Items", HaveLen(0)))
		Eventually(ObjectList(&metalv1alpha1.MachineList{})).Should(HaveField("Items", HaveLen(0)))
		Eventually(ObjectList(&metalv1alpha1.OOBList{})).Should(HaveField("Items", HaveLen(0)))
		Eventually(ObjectList(&metalv1alpha1.OOBSecretList{})).Should(HaveField("Items", HaveLen(0)))

		DeferCleanup(func(ctx SpecContext) {
			Eventually(ctx, func(g Gomega, ctx SpecContext) {
				var ips ipamv1alpha1.IPList
				g.Expect(ObjectList(&ips)()).To(SatisfyAll())
				if len(ips.Items) > 0 {
					g.Expect(k8sClient.DeleteAllOf(ctx, &ips.Items[0], &client.DeleteAllOfOptions{
						ListOptions: client.ListOptions{
							Namespace: OOBTemporaryNamespaceHack,
						},
					})).To(Succeed())
				}
				var machines metalv1alpha1.MachineList
				g.Expect(ObjectList(&machines)()).To(SatisfyAll())
				if len(machines.Items) > 0 {
					g.Expect(k8sClient.DeleteAllOf(ctx, &machines.Items[0])).To(Succeed())
				}
				var oobs metalv1alpha1.OOBList
				g.Expect(ObjectList(&oobs)()).To(SatisfyAll())
				if len(oobs.Items) > 0 {
					g.Expect(k8sClient.DeleteAllOf(ctx, &oobs.Items[0])).To(Succeed())
				}
				var secrets metalv1alpha1.OOBSecretList
				g.Expect(ObjectList(&secrets)()).To(SatisfyAll())
				if len(secrets.Items) > 0 {
					g.Expect(k8sClient.DeleteAllOf(ctx, &secrets.Items[0])).To(Succeed())
				}

				g.Expect(ObjectList(&ips)()).To(HaveField("Items", BeEmpty()))
				g.Expect(ObjectList(&machines)()).To(HaveField("Items", BeEmpty()))
				g.Expect(ObjectList(&oobs)()).To(HaveField("Items", BeEmpty()))
				g.Expect(ObjectList(&secrets)()).To(HaveField("Items", BeEmpty()))
			}, time.Second*3).Should(Succeed())
		})
	})

	It("should create an OOB from an IP", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}

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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting finalizer, mac, and endpointref to be correct on the OOB")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Listing machines")
		machines := &metalv1alpha1.MachineList{}
		Eventually(ObjectList(machines)).Should(HaveField("Items", HaveLen(1)))
		machine := &machines.Items[0]

		By("Expecting Machine to have the correct data")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Spec.UUID", machine.Name),
			HaveField("Spec.OOBRef.Name", oob.Name),
			HaveField("Status.Manufacturer", "Fake"),
			HaveField("Status.SKU", "Fake-0"),
			HaveField("Status.SerialNumber", "1"),
			HaveField("Status.Power", metalv1alpha1.PowerOff),
			HaveField("Status.LocatorLED", metalv1alpha1.LEDOff),
		))
	})

	It("should control locator LED", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}

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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Listing machines")
		machines := &metalv1alpha1.MachineList{}
		Eventually(ObjectList(machines)).Should(HaveField("Items", HaveLen(1)))
		machine := &machines.Items[0]

		By("Setting LED to lit")
		Eventually(Update(machine, func() {
			machine.Spec.LocatorLED = metalv1alpha1.LEDLit
		})).Should(Succeed())

		By("Expecting LED to be lit")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Status.LocatorLED", metalv1alpha1.LEDLit),
		))

		By("Setting LED to blinking")
		Eventually(Update(machine, func() {
			machine.Spec.LocatorLED = metalv1alpha1.LEDBlinking
		})).Should(Succeed())

		By("Expecting LED to be blinking")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Status.LocatorLED", metalv1alpha1.LEDBlinking),
		))

		By("Setting LED to off")
		Eventually(Update(machine, func() {
			machine.Spec.LocatorLED = metalv1alpha1.LEDOff
		})).Should(Succeed())

		By("Expecting LED to be off")
		Eventually(Object(machine)).Should(SatisfyAll(
			HaveField("Status.LocatorLED", metalv1alpha1.LEDOff),
		))
	})

	It("should control power", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}

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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Listing machines")
		machines := &metalv1alpha1.MachineList{}
		Eventually(ObjectList(machines)).Should(HaveField("Items", HaveLen(1)))
		machine := &machines.Items[0]

		By("Setting power to on")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOn
		})).Should(Succeed())

		By("Expecting machine to be on")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting power to off")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOff
		})).Should(Succeed())

		By("Expecting machine to be off and annotation to be cleared")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOff),
		))

		By("Setting power to on")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOn
		})).Should(Succeed())

		By("Expecting machine to be on")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting power to force off")
		Eventually(Update(machine, func() {
			if machine.Annotations == nil {
				machine.Annotations = make(map[string]string, 1)
			}
			machine.Annotations[metalv1alpha1.MachineOperationKeyName] = metalv1alpha1.MachineOperationForceOff
			machine.Spec.Power = metalv1alpha1.PowerOff
		})).Should(Succeed())

		By("Expecting machine to be off and annotation to be cleared")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOff),
		))

		By("Setting power to on")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOn
		})).Should(Succeed())

		By("Expecting machine to be on")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting power to off while the machine is hanging")
		Eventually(Update(oob, func() {
			oob.Spec.Flags = map[string]string{
				"fake.power": "stuck",
			}
		})).Should(Succeed())
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOff
		})).Should(Succeed())

		By("Expecting machine to be off and annotation to be cleared")
		Eventually(Object(machine), timeToReady+shutdownTimeout).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOff),
		))
	})

	It("should restart", func(ctx SpecContext) {
		oob := &metalv1alpha1.OOB{
			ObjectMeta: metav1.ObjectMeta{
				Name: mac,
			},
		}

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

		By("Patching IP reservation and state")
		ipAddr, err := ipamv1alpha1.IPAddrFromString("1.2.3.4")
		Expect(err).NotTo(HaveOccurred())
		Eventually(UpdateStatus(ip, func() {
			ip.Status.Reserved = ipAddr
			ip.Status.State = ipamv1alpha1.CFinishedIPState
		})).Should(Succeed())

		By("Expecting the OOB to have the correct info")
		Eventually(Object(oob), timeToReady).Should(SatisfyAll(
			HaveField("Status.Type", metalv1alpha1.OOBTypeMachine),
			HaveField("Status.State", metalv1alpha1.OOBStateReady),
			WithTransform(readyReason, Equal(metalv1alpha1.OOBConditionReasonReady)),
		))

		By("Listing machines")
		machines := &metalv1alpha1.MachineList{}
		Eventually(ObjectList(machines)).Should(HaveField("Items", HaveLen(1)))
		machine := &machines.Items[0]

		By("Setting power to on")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOn
		})).Should(Succeed())

		By("Expecting machine to be on")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting restart annotation")
		Eventually(Update(machine, func() {
			if machine.Annotations == nil {
				machine.Annotations = make(map[string]string, 1)
			}
			machine.Annotations[metalv1alpha1.MachineOperationKeyName] = metalv1alpha1.MachineOperationRestart
		})).Should(Succeed())

		By("Expecting machine to be on and annotation to be cleared")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting force restart annotation")
		Eventually(Update(machine, func() {
			if machine.Annotations == nil {
				machine.Annotations = make(map[string]string, 1)
			}
			machine.Annotations[metalv1alpha1.MachineOperationKeyName] = metalv1alpha1.MachineOperationForceRestart
		})).Should(Succeed())

		By("Expecting machine to be on and annotation to be cleared")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOn),
		))

		By("Setting power to off")
		Eventually(Update(machine, func() {
			machine.Spec.Power = metalv1alpha1.PowerOff
		})).Should(Succeed())

		By("Expecting machine to be off")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			HaveField("Status.Power", metalv1alpha1.PowerOff),
		))

		By("Setting restart annotation")
		Eventually(Update(machine, func() {
			if machine.Annotations == nil {
				machine.Annotations = make(map[string]string, 1)
			}
			machine.Annotations[metalv1alpha1.MachineOperationKeyName] = metalv1alpha1.MachineOperationRestart
		})).Should(Succeed())

		By("Expecting machine to be off and annotation to be cleared")
		Eventually(Object(machine), timeToReady).Should(SatisfyAll(
			Not(HaveField("Annotations", HaveKey(metalv1alpha1.MachineOperationKeyName))),
			HaveField("Status.Power", metalv1alpha1.PowerOff),
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
