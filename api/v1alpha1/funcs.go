package v1alpha1

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/inf.v0"
	"k8s.io/apimachinery/pkg/api/resource"
)

func makeAggregate(theType AggregateType, values []reflect.Value) (*resource.Quantity, error) {
	switch theType {
	case MaxAggregateType:
		return maxAggregate(values)
	case MinAggregateType:
		return minAggregate(values)
	case CountAggregateType:
		return countAggregate(values), nil
	case SumAggregateType:
		return sumAggregate(values)
	case AverageAggregateType:
		return averageAggregate(values)
	}
	return nil, errors.Errorf("unknown aggregation type %s", theType)
}

func minAggregate(values []reflect.Value) (*resource.Quantity, error) {
	minimum, err := valueToQuantity(&values[0])
	if err != nil {
		return nil, errors.Wrapf(err, "unable to convert value to quantity")
	}
	for i := 1; i < len(values); i++ {
		curr, err := valueToQuantity(&values[i])
		if err != nil {
			return nil, errors.Wrapf(err, "unable to convert value to quantity")
		}
		if minimum.Cmp(*curr) > 0 {
			minimum = curr
		}
	}
	return minimum, nil
}

func maxAggregate(values []reflect.Value) (*resource.Quantity, error) {
	maximum, err := valueToQuantity(&values[0])
	if err != nil {
		return nil, errors.Wrapf(err, "unable to convert value to quantity")
	}
	for i := 1; i < len(values); i++ {
		curr, err := valueToQuantity(&values[i])
		if err != nil {
			return nil, errors.Wrapf(err, "unable to convert value to quantity")
		}
		if maximum.Cmp(*curr) < 0 {
			maximum = curr
		}
	}
	return maximum, nil
}

func sumAggregate(values []reflect.Value) (*resource.Quantity, error) {
	sum := resource.NewScaledQuantity(0, 0)
	for _, value := range values {
		q, err := valueToQuantity(&value)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to convert value to quantity")
		}
		sum.Add(*q)
	}
	return sum, nil
}

func averageAggregate(values []reflect.Value) (*resource.Quantity, error) {
	sum, err := sumAggregate(values)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to calculate aggregate")
	}
	decVal := sum.AsDec()
	divInt := len(values)
	div := inf.NewDec(int64(divInt), 0)
	res := decVal.QuoExact(decVal, div)
	if res == nil {
		return nil, errors.Errorf("quotient of %s/%s is not finite decimal", decVal.String(), div.String())
	}
	agg := resource.MustParse(res.String())
	return &agg, nil
}

func countAggregate(values []reflect.Value) *resource.Quantity {
	return resource.NewScaledQuantity(int64(len(values)), 0)
}

func setValueToPath(theMap map[string]interface{}, tokenizedPath []string, valueToSet interface{}) error {
	lastTokenIdx := len(tokenizedPath) - 1
	var prevVal interface{} = theMap
	for idx, token := range tokenizedPath {
		currMap, ok := prevVal.(map[string]interface{})
		// if previous value is empty struct, but there are still tokens
		// then parent path is used to set value, and it is not possible
		// to set value in child path
		if !ok {
			return errors.Errorf("can not use path %s to set value, as parent path %s already used to set value", strings.Join(tokenizedPath, "."), strings.Join(tokenizedPath[:idx+1], "."))
		}

		currVal, ok := currMap[token]
		// if value is not set
		if !ok {
			// if it is the last token, then set empty struct
			if idx == lastTokenIdx {
				currMap[token] = valueToSet
				// otherwise create a map
			} else {
				currMap[token] = make(map[string]interface{})
			}
			// if value is set
		} else {
			_, ok := currVal.(map[string]interface{})
			// if value is not map and it is the last token,
			// then there is a duplicate path
			if !ok && idx == lastTokenIdx {
				return errors.Errorf("duplicate path %s", strings.Join(tokenizedPath, "."))
			}
			// if it is map and it is the last token,
			// then there is a child path used to set value
			if ok && idx == lastTokenIdx {
				return errors.Errorf("can not use path %s to set value, as there is a child path", strings.Join(tokenizedPath, "."))
			}
			// if it is not a map, and it is not the last token,
			// then there is parent path used to set value
			if !ok && idx != lastTokenIdx {
				return errors.Errorf("can not use path %s to set value, as parent path %s already used to set value", strings.Join(tokenizedPath, "."), strings.Join(tokenizedPath[:idx+1], "."))
			}
			// if it is a map, and it is not the last token,
			// then continue
		}
		prevVal = currMap[token]
	}

	return nil
}

func valueToString(value *reflect.Value) (string, error) {
	nonPointerValue := *value
	for {
		if nonPointerValue.Kind() == reflect.Ptr {
			nonPointerValue = nonPointerValue.Elem()
		} else {
			break
		}
	}

	if nonPointerValue.Kind() == reflect.Interface {
		nonPointerValue = reflect.ValueOf(nonPointerValue.Interface())
	}

	if nonPointerValue.Kind() != reflect.String {
		return "", errors.Errorf("unsupported kind %s for literal comparison", nonPointerValue.Kind().String())
	}
	s, ok := nonPointerValue.Interface().(string)
	if !ok {
		return "", errors.Errorf("valueToString: type assertions failed")
	}
	return s, nil
}

// nolint:forcetypeassert
func valueToQuantity(value *reflect.Value) (*resource.Quantity, error) {
	nonPointerValue := *value
	for {
		if nonPointerValue.Kind() == reflect.Ptr {
			nonPointerValue = nonPointerValue.Elem()
		} else {
			break
		}
	}

	if nonPointerValue.Kind() == reflect.Interface {
		nonPointerValue = reflect.ValueOf(nonPointerValue.Interface())
	}

	switch nonPointerValue.Kind() {
	case reflect.String:
		v := nonPointerValue.Interface().(string)
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, err
		}
		return &q, nil
	case reflect.Int:
		v := nonPointerValue.Interface().(int)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Int8:
		v := nonPointerValue.Interface().(int8)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Int16:
		v := nonPointerValue.Interface().(int16)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Int32:
		v := nonPointerValue.Interface().(int32)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Int64:
		v := nonPointerValue.Interface().(int64)
		q := resource.NewScaledQuantity(v, 0)
		return q, nil
	case reflect.Uint:
		v := nonPointerValue.Interface().(uint)
		q := resource.MustParse(fmt.Sprintf("%d", v))
		return &q, nil
	case reflect.Uint8:
		v := nonPointerValue.Interface().(uint8)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Uint16:
		v := nonPointerValue.Interface().(uint16)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Uint32:
		v := nonPointerValue.Interface().(uint32)
		q := resource.NewScaledQuantity(int64(v), 0)
		return q, nil
	case reflect.Uint64:
		v := nonPointerValue.Interface().(uint64)
		q := resource.MustParse(fmt.Sprintf("%d", v))
		return &q, nil
	case reflect.Float32:
		v := nonPointerValue.Interface().(float32)
		q := resource.MustParse(fmt.Sprintf("%f", v))
		return &q, nil
	case reflect.Float64:
		v := nonPointerValue.Interface().(float64)
		q := resource.MustParse(fmt.Sprintf("%f", v))
		return &q, nil
	case reflect.Struct:
		v, ok := nonPointerValue.Interface().(resource.Quantity)
		if !ok {
			return nil, errors.Errorf("unsupported struct type %s for numeric comparison", nonPointerValue.Type().String())
		}
		return &v, nil
	default:
		return nil, errors.Errorf("unsupported kind %s for numeric comparison", nonPointerValue.Kind().String())
	}
}

func normalizeJSONPath(jp string) string {
	if strings.HasPrefix(jp, "{.") {
		return jp
	}
	if strings.HasPrefix(jp, ".") {
		return fmt.Sprintf("{%s}", jp)
	}
	return fmt.Sprintf("{.%s}", jp)
}

type ValidationInventory struct {
	Spec InventorySpec `json:"spec"`
}
