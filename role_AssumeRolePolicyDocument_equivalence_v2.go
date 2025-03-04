package rampolicyequivalence

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"reflect"
)

type intermediatePolicyACS struct {
	Version   string      `json:",omitempty"`
	Statement interface{} `json:"Statement"`
}

type policyACS struct {
	Version   string
	Statement []*policyStatementACS
}

type policyStatementACS struct {
	Effect    string       `json:"Effect,omitempty" mapstructure:"Effect"`
	Action    interface{}  `json:"Action,omitempty" mapstructure:"Action"`
	NotAction interface{}  `json:"NotAction,omitempty" mapstructure:"NotAction"`
	Principal PrincipalMap `json:"Principal,omitempty" mapstructure:"Principal"`
	Condition ConditionMap `json:"Condition,omitempty" mapstructure:"Condition"`
}

func AssumeRolePolicyDocumentAreEquivalentV2(policy1, policy2 string) (bool, error) {
	var policy1intermediate, policy2intermediate intermediatePolicyACS

	err := json.Unmarshal([]byte(policy1), &policy1intermediate)
	if err != nil {
		return false, fmt.Errorf("unmarshal policy1 failed: %w", err)
	}

	err = json.Unmarshal([]byte(policy2), &policy2intermediate)
	if err != nil {
		return false, fmt.Errorf("unmarshal policy2 failed: %w", err)
	}

	if reflect.DeepEqual(policy1intermediate, policy2intermediate) {
		return true, nil
	}

	policy1ACS, err := policy1intermediate.document()
	if err != nil {
		return false, fmt.Errorf("parsing policy 1: %s", err)
	}

	policy2ACS, err := policy2intermediate.document()
	if err != nil {
		return false, fmt.Errorf("parsing policy 2: %s", err)
	}

	for i := range policy1ACS.Statement {
		if err := normalizePrincipal(&policy1ACS.Statement[i].Principal); err != nil {
			return false, err
		}
	}

	for i := range policy2ACS.Statement {
		if err := normalizePrincipal(&policy2ACS.Statement[i].Principal); err != nil {
			return false, err
		}
	}

	return policy1ACS.Equals(policy2ACS), nil
}

func (intermediate *intermediatePolicyACS) document() (*policyACS, error) {
	var statement []*policyStatementACS
	if intermediate.Statement != nil {
		switch s := intermediate.Statement.(type) {
		case []interface{}:
			config := &mapstructure.DecoderConfig{
				Result:      &statement,
				ErrorUnused: true,
			}
			decoder, err := mapstructure.NewDecoder(config)
			if err != nil {
				return nil, err
			}
			err = decoder.Decode(s)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unknown statement parsing problem")
		}
	}

	policy := &policyACS{
		Version:   intermediate.Version,
		Statement: statement,
	}

	return policy, nil
}

func (p *policyACS) Equals(other *policyACS) bool {
	if p.Version != other.Version || len(p.Statement) != len(other.Statement) {
		return false
	}

	for i := range p.Statement {
		if !p.Statement[i].Equals(other.Statement[i]) {
			return false
		}
	}

	return true
}

func (s *policyStatementACS) Equals(other *policyStatementACS) bool {
	if !equalActionOrNotAction(s.Action, other.Action) || !equalActionOrNotAction(s.NotAction, other.NotAction) || s.Effect != other.Effect || !s.Principal.Equals(other.Principal) || !s.Condition.Equals(other.Condition) {
		return false
	}
	return true
}

func equalActionOrNotAction(a, b interface{}) bool {
	if a == nil {
		return b == nil
	}
	switch aTyped := a.(type) {
	case string:
		if bTyped, ok := b.(string); ok && aTyped == bTyped {
			return true
		}
	case []string:
		if bTyped, ok := b.([]string); ok && len(aTyped) == len(bTyped) {
			for i, v := range aTyped {
				if v != bTyped[i] {
					return false
				}
			}
			return true
		}
	}
	return false
}

func (pm PrincipalMap) Equals(other PrincipalMap) bool {
	if len(pm) != len(other) {
		return false
	}

	for key, value := range pm {
		if !compareValues(value, other[key]) {
			return false
		}
	}

	return true
}

func (cm ConditionMap) Equals(other ConditionMap) bool {
	if cm == nil {
		return other == nil
	}

	if len(cm) != len(other) {
		return false
	}

	for key, value := range cm {
		if !compareValues(value, other[key]) {
			return false
		}
	}

	return true
}

func compareValues(a, b interface{}) bool {
	switch a := a.(type) {
	case string:
		bStr, ok := b.(string)
		return ok && a == bStr
	case []string:
		bArr, ok := b.([]string)
		return ok && len(a) == len(bArr) && equalStrings(a, bArr)
	case []interface{}:
		bArr, ok := b.([]interface{})
		return ok && len(a) == len(bArr) && equalInterfaces(a, bArr)
	case map[string]interface{}:
		bMap, ok := b.(map[string]interface{})
		if !ok || len(a) != len(bMap) {
			return false
		}
		for key, value := range a {
			if !compareValues(value, bMap[key]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func equalStrings(a, b []string) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalInterfaces(a, b []interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if !compareValues(v, b[i]) {
			return false
		}
	}
	return true
}
