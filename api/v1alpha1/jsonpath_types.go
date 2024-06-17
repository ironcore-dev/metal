// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/jsonpath"
)

// +kubebuilder:validation:Type=string
type JSONPath struct {
	Path string `json:"-"`
}

func (in *JSONPath) MarshalJSON() ([]byte, error) {
	str := in.String()
	return json.Marshal(str)
}

// nolint:forcetypeassert
func (in *JSONPath) UnmarshalJSON(b []byte) error {
	stringVal := string(b)
	if stringVal == null {
		return nil
	}
	if err := json.Unmarshal(b, &stringVal); err != nil {
		return err
	}

	stringVal = normalizeJSONPath(stringVal)
	jp := jsonpath.New(stringVal)
	if err := jp.Parse(stringVal); err != nil {
		return errors.Wrap(err, "unable to parse JSONPath")
	}

	parser := jsonpath.NewParser(stringVal)
	if err := parser.Parse(stringVal); err != nil {
		return errors.Wrap(err, "unable to parse JSONPath")
	}
	if len(parser.Root.Nodes) != 1 || parser.Root.Nodes[0].Type() != jsonpath.NodeList {
		return errors.New("path should have exactly one path expression")
	}

	nodeList := parser.Root.Nodes[0].(*jsonpath.ListNode)
	for idx, node := range nodeList.Nodes {
		nodeType := node.Type()
		if !(nodeType == jsonpath.NodeField || nodeType == jsonpath.NodeArray) {
			return errors.Errorf("path contains segment %d, %s that is not a field name", idx, node.String())
		}
	}

	in.Path = stringVal

	return nil
}

func JSONPathFromString(s string) *JSONPath {
	return &JSONPath{
		Path: normalizeJSONPath(s),
	}
}

func (in *JSONPath) String() string {
	return normalizeJSONPath(in.Path)
}

func (in *JSONPath) ToK8sJSONPath() (*jsonpath.JSONPath, error) {
	jp := jsonpath.New(in.Path)
	if err := jp.Parse(in.Path); err != nil {
		return nil, errors.Wrap(err, "unable to parse JSONPath")
	}
	return jp, nil
}

func (in *JSONPath) Tokenize() []string {
	trimmed := strings.Trim(in.Path, "{.}")
	return strings.Split(trimmed, ".")
}
