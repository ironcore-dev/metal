// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	MachineOperationKeyName      string = "machine.metal.ironcore.dev/operation"
	MachineOperationRestart      string = "Restart"
	MachineOperationForceRestart string = "ForceRestart"
	MachineOperationForceOff     string = "ForceOff"
)

// MachineSpec defines the desired state of Machine
type MachineSpec struct {
	//+kubebuilder:validation:Pattern=`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	UUID string `json:"uuid"`

	OOBRef v1.LocalObjectReference `json:"oobRef"`

	InventoryRef *v1.LocalObjectReference `json:"inventoryRef,omitempty"`

	//+optional
	MachineClaimRef *v1.ObjectReference `json:"machineClaimRef,omitempty"`

	//+optional
	LoopbackAddressRef *v1.LocalObjectReference `json:"loopbackAddressRef,omitempty"`

	//+optional
	ASN string `json:"asn,omitempty"`

	//+optional
	Power Power `json:"power,omitempty"` // TODO: Revisit whether this is really optional.

	//+optional
	LocatorLED LocatorLED `json:"locatorLED,omitempty"`
}

type Power string

const (
	PowerOn  Power = "On"
	PowerOff Power = "Off"
)

type LocatorLED string

const (
	LocatorLEDOn       Power = "On"
	LocatorLEDOff      Power = "Off"
	LocatorLEDBlinking Power = "Blinking"
)

// MachineStatus defines the observed state of Machine
type MachineStatus struct {
	//+optional
	Manufacturer string `json:"manufacturer,omitempty"`

	//+optional
	SKU string `json:"sku,omitempty"`

	//+optional
	SerialNumber string `json:"serialNumber,omitempty"`

	//+optional
	Power Power `json:"power,omitempty"`

	//+optional
	LocatorLED LocatorLED `json:"locatorLED,omitempty"`

	//+optional
	ShutdownDeadline *metav1.Time `json:"shutdownDeadline,omitempty"`

	//+optional
	NetworkInterfaces []MachineNetworkInterface `json:"networkInterfaces"`

	//+optional
	State MachineState `json:"state,omitempty"`

	//+patchStrategy=merge
	//+patchMergeKey=type
	//+optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

type MachineNetworkInterface struct {
	Name string `json:"name"`

	//+kubebuilder:validation:Pattern=`^[0-9a-f]{12}$`
	MacAddress string `json:"macAddress"`

	//+optional
	IPRef *v1.LocalObjectReference `json:"IPRef,omitempty"`

	//+optional
	SwitchRef *v1.LocalObjectReference `json:"switchRef,omitempty"`
}

type MachineState string

const (
	MachineStateReady MachineState = "Ready"
	MachineStateError MachineState = "Error"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="UUID",type=string,JSONPath=`.status.uuid`
//+kubebuilder:printcolumn:name="Manufacturer",type=string,JSONPath=`.status.manufacturer`
//+kubebuilder:printcolumn:name="SKU",type=string,JSONPath=`.status.sku`,priority=100
//+kubebuilder:printcolumn:name="SerialNumber",type=string,JSONPath=`.status.serialNumber`,priority=100
//+kubebuilder:printcolumn:name="Power",type=string,JSONPath=`.status.power`
//+kubebuilder:printcolumn:name="LocatorLED",type=string,JSONPath=`.status.locatorLED`,priority=100
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// Machine is the Schema for the machines API
type Machine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MachineSpec   `json:"spec,omitempty"`
	Status MachineStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// MachineList contains a list of Machine
type MachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Machine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Machine{}, &MachineList{})
}
