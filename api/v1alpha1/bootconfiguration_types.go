// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BootConfigurationSpec defines the desired state of BootConfiguration
type BootConfigurationSpec struct {
	MachineRef *v1.LocalObjectReference `json:"machineRef"`

	IgnitionSecretRef *v1.ObjectReference `json:"ignitionSecretRef"`

	Image string `json:"image"`
}

// BootConfigurationStatus defines the observed state of BootConfiguration
type BootConfigurationStatus struct {
	// +kubebuilder:validation:Enum=Ready;Pending;Error
	// +optional
	State BootConfigurationState `json:"state,omitempty"`
}

type BootConfigurationState string

const (
	BootConfigurationStateReady   BootConfigurationState = "Ready"
	BootConfigurationStatePending BootConfigurationState = "Pending"
	BootConfigurationStateError   BootConfigurationState = "Error"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +genclient

// BootConfiguration is the Schema for the bootconfigurations API
type BootConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BootConfigurationSpec   `json:"spec,omitempty"`
	Status BootConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BootConfigurationList contains a list of BootConfiguration
type BootConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BootConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BootConfiguration{}, &BootConfigurationList{})
}
