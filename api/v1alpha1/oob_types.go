// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	OOBOperationKeyName string = "oob.metal.ironcore.dev/operation"
	OOBOperationRestart string = "Restart"
)

// OOBSpec defines the desired state of OOB
type OOBSpec struct {
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{12}$`
	MACAddress string `json:"macAddress"`

	// +optional
	EndpointRef *v1.LocalObjectReference `json:"endpointRef,omitempty"`

	// +optional
	SecretRef *v1.LocalObjectReference `json:"secretRef,omitempty"`

	// +optional
	Protocol *Protocol `json:"protocol,omitempty"`

	// +optional
	Flags map[string]string `json:"flags,omitempty"`

	// +optional
	ConsoleProtocol *ConsoleProtocol `json:"consoleProtocol,omitempty"`
}

type Protocol struct {
	Name ProtocolName `json:"name"`
	Port int32        `json:"port"`
}

type ProtocolName string

const (
	ProtocolNameRedfish ProtocolName = "Redfish"
	ProtocolNameIPMI    ProtocolName = "IPMI"
	ProtocolNameSSH     ProtocolName = "SSH"
)

type ConsoleProtocol struct {
	Name ConsoleProtocolName `json:"name"`
	Port int32               `json:"port"`
}

type ConsoleProtocolName string

const (
	ConsoleProtocolNameIPMI      ConsoleProtocolName = "IPMI"
	ConsoleProtocolNameSSH       ConsoleProtocolName = "SSH"
	ConsoleProtocolNameSSHLenovo ConsoleProtocolName = "SSHLenovo"
)

// OOBStatus defines the observed state of OOB
type OOBStatus struct {
	// +kubebuilder:validation:Enum=Machine;Router;Switch
	// +optional
	Type OOBType `json:"type,omitempty"`

	// +optional
	Manufacturer string `json:"manufacturer,omitempty"`

	// +optional
	SKU string `json:"sku,omitempty"`

	// +optional
	SerialNumber string `json:"serialNumber,omitempty"`

	// +optional
	FirmwareVersion string `json:"firmwareVersion,omitempty"`

	// +kubebuilder:validation:Enum=Ready;Unready;Ignored;Error
	// +optional
	State OOBState `json:"state,omitempty"`

	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

type OOBType string

const (
	OOBTypeMachine OOBType = "Machine"
	OOBTypeRouter  OOBType = "Router"
	OOBTypeSwitch  OOBType = "Switch"
)

type OOBState string

const (
	OOBStateReady   OOBState = "Ready"
	OOBStateUnready OOBState = "Unready"
	OOBStateIgnored OOBState = "Ignored"
	OOBStateError   OOBState = "Error"
)

const (
	OOBConditionTypeReady        = "Ready"
	OOBConditionReasonInProgress = "InProgress"
	OOBConditionReasonNoEndpoint = "NoEndpoint"
	OOBConditionReasonIgnored    = "Ignored"
	OOBConditionReasonError      = "Error"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="MACAddress",type=string,JSONPath=`.spec.macAddress`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.status.type`
// +kubebuilder:printcolumn:name="Manufacturer",type=string,JSONPath=`.status.manufacturer`
// +kubebuilder:printcolumn:name="SKU",type=string,JSONPath=`.status.sku`,priority=100
// +kubebuilder:printcolumn:name="SerialNumber",type=string,JSONPath=`.status.serialNumber`,priority=100
// +kubebuilder:printcolumn:name="FirmwareVersion",type=string,JSONPath=`.status.firmwareVersion`,priority=100
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// OOB is the Schema for the oobs API
type OOB struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OOBSpec   `json:"spec,omitempty"`
	Status OOBStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OOBList contains a list of OOB
type OOBList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OOB `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OOB{}, &OOBList{})
}
