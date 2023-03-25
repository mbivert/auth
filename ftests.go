package auth

import (
	"testing"
	"reflect"
	"strings"
	"runtime"
	"fmt"
	"encoding/json" // pretty-printing
)

type test struct {
	name     string
	fun      interface{}
	args     []interface{}
	expected []interface{}
}

func getFn(f interface{}) string {
	xs := strings.Split((runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()), ".")
	return xs[len(xs)-1]
}

func doTest(t *testing.T, f interface{}, args []interface{}, expected []interface{}) {
	// []interface{} -> []reflect.Value
	var vargs []reflect.Value
	for _, v := range args {
		vargs = append(vargs, reflect.ValueOf(v))
	}

	got := reflect.ValueOf(f).Call(vargs)

	// []reflect.Value -> []interface{}
	var igot []interface{}
	for _, v := range got {
		igot = append(igot, v.Interface())
	}

	if !reflect.DeepEqual(igot, expected) {
		sgot, err := json.MarshalIndent(igot, "", "\t")
		if err != nil {
			sgot = []byte(fmt.Sprintf("%+v (%s)", igot, err))
		}
		sexp, err := json.MarshalIndent(expected, "", "\t")
		if err != nil {
			sexp = []byte(fmt.Sprintf("%+v (%s)", expected, err))
		}
		// errors are printed as {} with JSON (unexported fields)
		fmt.Printf("got: '%s', expected: '%s'", igot, expected)
		t.Fatalf("got: '%s', expected: '%s'", sgot, sexp)
	}
}

func doTests(t *testing.T, tests []test) {
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s()/%s", getFn(test.fun), test.name), func(t *testing.T) {
			doTest(t, test.fun, test.args, test.expected)
		})
	}
}
