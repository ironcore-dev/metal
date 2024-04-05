// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MachineClaimSpec defines the desired state of MachineClaim
// TODO: Validate that exactly one of MachineRef or MachineSelector is set.
type MachineClaimSpec struct {
	// +optional
	MachineRef *v1.LocalObjectReference `json:"machineRef,omitempty"`

	// +optional
	MachineSelector *metav1.LabelSelector `json:"machineSelector,omitempty"`

	Image string `json:"image"`

	// +kubebuilder:validation:Enum=On;Off
	Power Power `json:"power"`

	// +optional
	IgnitionSecretRef *v1.LocalObjectReference `json:"ignitionSecretRef,omitempty"`

	// +optional
	NetworkInterfaces []MachineClaimNetworkInterface `json:"networkInterfaces,omitempty"`
}

type MachineClaimNetworkInterface struct {
	Name string `json:"name"`

	Prefix Prefix `json:"prefix"`
}

// MachineClaimStatus defines the observed state of MachineClaim
type MachineClaimStatus struct {
	// +kubebuilder:validation:Enum=Bound;Unbound
	// +optional
	Phase MachineClaimPhase `json:"phase,omitempty"`
}

type MachineClaimPhase string

const (
	MachineClaimPhaseBound   MachineClaimPhase = "Bound"
	MachineClaimPhaseUnbound MachineClaimPhase = "Unbound"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// MachineClaim is the Schema for the machineclaims API
type MachineClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MachineClaimSpec   `json:"spec,omitempty"`
	Status MachineClaimStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MachineClaimList contains a list of MachineClaim
type MachineClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MachineClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MachineClaim{}, &MachineClaimList{})
}
