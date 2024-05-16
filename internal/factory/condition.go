package factory

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ConditionProperty interface {
	apply(*metav1.Condition)
}

type conditionType string

func (c conditionType) apply(condition *metav1.Condition) {
	condition.Type = string(c)
}

func ConditionType(value string) ConditionProperty {
	return conditionType(value)
}

type conditionStatus metav1.ConditionStatus

func (c conditionStatus) apply(condition *metav1.Condition) {
	condition.Status = metav1.ConditionStatus(c)
}

func ConditionStatus(status metav1.ConditionStatus) ConditionProperty {
	return conditionStatus(status)
}

type conditionReason string

func (c conditionReason) apply(condition *metav1.Condition) {
	condition.Reason = string(c)
}

func ConditionReason(reason string) ConditionProperty {
	return conditionReason(reason)
}

type conditionMessage string

func (c conditionMessage) apply(condition *metav1.Condition) {
	condition.Message = string(c)
}

func ConditionMessage(message string) ConditionProperty {
	return conditionMessage(message)
}

type observedGeneration int64

func (c observedGeneration) apply(condition *metav1.Condition) {
	condition.ObservedGeneration = int64(c)
}

func ObservedGeneration(value int64) ConditionProperty {
	return observedGeneration(value)
}

type lastTransitionTime metav1.Time

func (c lastTransitionTime) apply(condition *metav1.Condition) {
	condition.LastTransitionTime = metav1.Time(c)
}

func LastTransitionTime(value metav1.Time) ConditionProperty {
	return lastTransitionTime(value)
}

type ConditionBuilder struct {
	condition  *metav1.Condition
	properties []ConditionProperty
}

func NewConditionBuilder(condition *metav1.Condition, properties ...ConditionProperty) *ConditionBuilder {
	return &ConditionBuilder{
		condition:  condition,
		properties: properties,
	}
}

func (b *ConditionBuilder) AddProperty(property ConditionProperty) *ConditionBuilder {
	b.properties = append(b.properties, property)
	return b
}

func (b *ConditionBuilder) Build() *metav1.Condition {
	for _, prop := range b.properties {
		prop.apply(b.condition)
	}
	return b.condition
}
