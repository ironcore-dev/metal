package v1alpha1

import (
	"strings"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SizeLabelPrefix = "metal.ironcore.dev/size-"

	AggregatePathPrefix            = "{.status.computed."
	AggregatePathPrefixReplacement = "{."
)

// SizeSpec defines the desired state of Size.
type SizeSpec struct {
	// Constraints is a list of selectors based on machine properties.
	// +kubebuilder:validation:Optional
	Constraints []ConstraintSpec `json:"constraints,omitempty"`
}

// SizeStatus defines the observed state of Size.
type SizeStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient

// Size is the Schema for the sizes API.
type Size struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SizeSpec   `json:"spec,omitempty"`
	Status SizeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SizeList contains a list of Size.
type SizeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Size `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Size{}, &SizeList{})
}

func GetSizeMatchLabel(sizeName string) string {
	return SizeLabelPrefix + sizeName
}

func (in *Size) GetMatchLabel() string {
	return SizeLabelPrefix + in.Name
}

func (in *Size) Matches(inventory *Inventory) (bool, error) {
	for _, constraint := range in.Spec.Constraints {
		// TODO think how or wait to improve on the hot fix
		// https://github.com/kubernetes-sigs/controller-tools/issues/287
		// nevertheless #1 is fixed, there is still an issue with kustomize dependency
		// https://github.com/kubernetes-sigs/kustomize/blob/f1b191c02fe046a043854092f5f03b4625f5614a/cmd/depprobcheck/README.md
		//
		// jsonpath library iterates over fields and doesn't care about tags.
		// I.e. AggregationResults is serialized into nested map (object), but in go code
		// it is represented by structure containing the exact inner map.
		// Means, jsonpath expects path to be like "status.computed.object.default..."
		// and not like "status.computed.default...".

		var queriedObject interface{} = inventory
		localJP := constraint.Path
		jpString := localJP.String()
		if strings.HasPrefix(jpString, AggregatePathPrefix) {
			jpString = AggregatePathPrefixReplacement + strings.TrimPrefix(jpString, AggregatePathPrefix)
			localJP = *JSONPathFromString(jpString)
			queriedObject = inventory.Status.Computed.Object
		}

		jp, err := localJP.ToK8sJSONPath()
		if err != nil {
			return false, err
		}

		// Do not return errors if data is not found
		jp.AllowMissingKeys(true)

		data, err := jp.FindResults(queriedObject)
		if err != nil {
			return false, err
		}

		dataLen := len(data)
		// If validation data is empty, return "does not match"
		if dataLen == 0 {
			return false, nil
		}
		// If data has more than 2 arrays, multiple result sets were returned
		// we do not support that case
		if dataLen > 1 {
			return false, errors.New("multiple selection results are not supported")
		}

		validationData := data[0]
		validationDataLen := len(validationData)
		// If result array is empty for some reason, return "does not match"
		if validationDataLen == 0 {
			return false, nil
		}

		var valid bool
		// If result set has only one value, validate it as a single value
		// even if it is an aggregate, since result will be the same
		if validationDataLen == 1 {
			valid, err = constraint.MatchSingleValue(&validationData[0])
		} else {
			valid, err = constraint.MatchMultipleValues(constraint.Aggregate, validationData)
		}

		if err != nil {
			return false, err
		}

		if !valid {
			return false, nil
		}
	}

	return true, nil
}
