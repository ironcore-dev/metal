// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OOBSecretSpec defines the desired state of OOBSecret
type OOBSecretSpec struct {
	//+kubebuilder:validation:Pattern=`^[0-9a-f]{12}$`
	MACAddress string `json:"macAddress"`

	Username string `json:"username"`

	Password string `json:"password"`

	//+optional
	ExpirationDate *metav1.Time `json:"expirationDate,omitempty"`
}

// OOBSecretStatus defines the observed state of OOBSecret
type OOBSecretStatus struct {
	//+patchStrategy=merge
	//+patchMergeKey=type
	//+optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="MACAddress",type=string,JSONPath=`.spec.macAddress`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimeStamp`
// +genclient

// OOBSecret is the Schema for the oobsecrets API
type OOBSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OOBSecretSpec   `json:"spec,omitempty"`
	Status OOBSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OOBSecretList contains a list of OOBSecret
type OOBSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OOBSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OOBSecret{}, &OOBSecretList{})
}
