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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	OOBOperationKeyName    string = "oob.metal.ironcore.dev/operation"
	OOBOperationReset      string = "Reset" //TODO: check proper names here
	OOBOperationForceReset string = "ForceReset"
)

// OOBSpec defines the desired state of OOB
type OOBSpec struct {
	//+kubebuilder:validation:Pattern=`^[0-9a-f]{12}$`
	MACAddress string `json:"macAddress"`

	EndpointRef v1.LocalObjectReference `json:"endpointRef"`

	SecretRef v1.LocalObjectReference `json:"secretRef"`

	Protocol Protocol `json:"protocol"`

	//+optional
	Flags map[string]string `json:"flags,omitempty"`

	//+optional
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

	Port int32 `json:"port"`
}

type ConsoleProtocolName string

const (
	ConsoleProtocolNameIPMI      ConsoleProtocolName = "IPMI"
	ConsoleProtocolNameSSH       ConsoleProtocolName = "SSH"
	ConsoleProtocolNameSSHLenovo ConsoleProtocolName = "SSHLenovo"
)

// OOBStatus defines the observed state of OOB
type OOBStatus struct {
	//+optional
	Type OOBType `json:"type,omitempty"`

	//+optional
	Manufacturer string `json:"manufacturer,omitempty"`

	//+optional
	SKU string `json:"sku,omitempty"`

	//+optional
	SerialNumber string `json:"serialNumber,omitempty"`

	//+optional
	FirmwareVersion string `json:"firmwareVersion,omitempty"`

	//+optional
	State OOBState `json:"state,omitempty"`

	//+patchStrategy=merge
	//+patchMergeKey=type
	//+optional
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
	OOBStateReady OOBState = "Ready"
	OOBStateError OOBState = "Error"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="MACAddress",type=string,JSONPath=`.spec.macAddress`
//+kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.status.type`
//+kubebuilder:printcolumn:name="Manufacturer",type=string,JSONPath=`.status.manufacturer`
//+kubebuilder:printcolumn:name="SKU",type=string,JSONPath=`.status.sku`,priority=100
//+kubebuilder:printcolumn:name="SerialNumber",type=string,JSONPath=`.status.serialNumber`,priority=100
//+kubebuilder:printcolumn:name="FirmwareVersion",type=string,JSONPath=`.status.firmwareVersion`,priority=100
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// OOB is the Schema for the oobs API
type OOB struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OOBSpec   `json:"spec,omitempty"`
	Status OOBStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OOBList contains a list of OOB
type OOBList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OOB `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OOB{}, &OOBList{})
}
