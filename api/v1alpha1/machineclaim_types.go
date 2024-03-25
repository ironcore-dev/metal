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

// MachineClaimSpec defines the desired state of MachineClaim
// TODO: Validate that exactly one of MachineRef or MachineSelector is set.
type MachineClaimSpec struct {
	//+optional
	MachineRef *v1.LocalObjectReference `json:"machineRef,omitempty"`

	//+optional
	MachineSelector *metav1.LabelSelector `json:"machineSelector,omitempty"`

	Image string `json:"image"`

	Power Power `json:"power"`

	//+optional
	IgnitionSecretRef *v1.LocalObjectReference `json:"ignitionSecretRef,omitempty"`

	//+optional
	NetworkInterfaces []MachineClaimNetworkInterface `json:"networkInterfaces,omitempty"` // todo is it optional?
}

type MachineClaimNetworkInterface struct {
	Name string `json:"name"`

	Prefix Prefix `json:"prefix"`
}

// MachineClaimStatus defines the observed state of MachineClaim
type MachineClaimStatus struct {
	//+optional
	Phase MachineClaimPhase `json:"phase,omitempty"`
}

type MachineClaimPhase string

const (
	MachineClaimPhaseBound   MachineClaimPhase = "Bound"
	MachineClaimPhaseUnbound MachineClaimPhase = "Unbound"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// MachineClaim is the Schema for the machineclaims API
type MachineClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MachineClaimSpec   `json:"spec,omitempty"`
	Status MachineClaimStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// MachineClaimList contains a list of MachineClaim
type MachineClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MachineClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MachineClaim{}, &MachineClaimList{})
}
