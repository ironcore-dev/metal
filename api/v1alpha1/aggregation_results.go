package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
)

// +kubebuilder:validation:Type=object
type AggregationResults struct {
	Object map[string]interface{} `json:"-"`
}

func (in *AggregationResults) MarshalJSON() ([]byte, error) {
	if in.Object == nil {
		return json.Marshal(map[string]interface{}{})
	}
	return json.Marshal(in.Object)
}

func (in *AggregationResults) UnmarshalJSON(b []byte) error {
	stringVal := string(b)
	if stringVal == null {
		in.Object = nil
		return nil
	}
	if err := json.Unmarshal(b, &in.Object); err != nil {
		return err
	}

	return nil
}

func (in *AggregationResults) DeepCopyInto(out *AggregationResults) {
	if in == nil {
		out = nil
	} else if in.Object == nil {
		out.Object = nil
	} else {
		out.Object = runtime.DeepCopyJSON(in.Object)
	}
}

func (in *AggregationResults) DeepCopy() *AggregationResults {
	if in == nil {
		return nil
	}
	out := new(AggregationResults)
	in.DeepCopyInto(out)
	return out
}
