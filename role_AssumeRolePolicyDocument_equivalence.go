package rampolicyequivalence

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type ConditionMap map[string]map[string]interface{}
type PrincipalMap map[string]interface{}

type Statement struct {
	Action    interface{}  `json:"Action,omitempty"`
	NotAction interface{}  `json:"NotAction,omitempty"`
	Effect    string       `json:"Effect"`
	Principal PrincipalMap `json:"Principal"`
	Condition ConditionMap `json:"Condition,omitempty"`
}

type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

/*
AssumeRolePolicyDocument可以包含Action、NotAction、Effect、Principal、Condition;
	且Action和NotAction可以为string或[]String
1.Ram对于空白字符、注释（/*格式)，输出时会去除(对于空白字符不返回diff, 而对/*格式注释也会输出diff)
2.Ram只会对Principal中的单个元素会处理为数组(不应返回diff)
3.用户写的user/role等删除后，ram输出的为id(应返回diff)
4.Ram API对于数组中元素的顺序不会进行改变(应返回diff)
5.改变json中key的顺序，API输出的顺序不变(不应返回diff)
6.用户更新username时，ram输出的username也会更新(应返回diff)
7.ram对于Principal中的key会转为大写(不应返回diff)

一个stmt中Action和NotAction只能出现一种(不需要增加校验逻辑，因为资源的属性一定不会出现该情况）
Principal中只能有RAM、SERVICE、FEDERATED（udf不检查是否有非法key）
Action中可以写注释"comments", ram会原样输出，不输出diff
*/

// todo：1.aws不检查非法的key输入(这样实际上是有问题的,如果用户在tf中写了invalid key, diff函数仍然会输出相等)

var validPrincipalKeys = [...]string{"RAM", "SERVICE", "FEDERATED"}

func AssumeRolePolicyDocumentAreEquivalent(policy1, policy2 string) (bool, error) {
	var p1, p2 Policy

	err := json.Unmarshal([]byte(policy1), &p1)
	if err != nil {
		return false, fmt.Errorf("unmarshal policy1 failed: %w", err)
	}

	err = json.Unmarshal([]byte(policy2), &p2)
	if err != nil {
		return false, fmt.Errorf("unmarshal policy2 failed: %w", err)
	}

	if reflect.DeepEqual(p1, p2) {
		return true, nil
	}

	for i := range p1.Statement {
		if err := normalizePrincipal(&p1.Statement[i].Principal); err != nil {
			return false, err
		}
	}

	for i := range p2.Statement {
		if err := normalizePrincipal(&p2.Statement[i].Principal); err != nil {
			return false, err
		}
	}

	//p1_b, _ := json.Marshal(p1)
	//p2_b, _ := json.Marshal(p2)
	//println(string(p1_b))
	//println(string(p2_b))

	return p1.Equals(p2), nil
}

func normalizePrincipal(principal *PrincipalMap) error {
	newPrincipal := make(PrincipalMap)
	for k, v := range *principal {
		upperK := strings.ToUpper(k)
		if !isValidPrincipalKey(upperK) {
			return errors.New(fmt.Sprintf("Invalid principal key: %s", upperK))
		}
		switch v := v.(type) {
		case string:
			newPrincipal[upperK] = []string{v}
		case []interface{}:
			strArray := make([]string, len(v))
			for i, val := range v {
				strArray[i] = val.(string)
			}
			newPrincipal[upperK] = strArray
		default:
			return errors.New(fmt.Sprintf("Invalid principal key-value pair, key: %s", k))
		}
	}
	*principal = newPrincipal
	return nil
}

func isValidPrincipalKey(key string) bool {
	for _, validKey := range validPrincipalKeys {
		if key == validKey {
			return true
		}
	}
	return false
}

func (p Policy) Equals(other Policy) bool {
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

func (s Statement) Equals(other Statement) bool {
	if !equalActionOrNotAction(s.Action, other.Action) || !equalActionOrNotAction(s.NotAction, other.NotAction) || s.Effect != other.Effect || !s.Principal.Equals(other.Principal) || !s.Condition.Equals(other.Condition) {
		//println(equalActionOrNotAction(s.Action, other.Action), equalActionOrNotAction(s.NotAction, other.NotAction), s.Effect == other.Effect, s.Principal.Equals(other.Principal), s.Condition.Equals(other.Condition))
		return false
	}

	return true
}
