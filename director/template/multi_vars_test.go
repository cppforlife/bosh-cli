package template_test

import (
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/bosh-cli/director/template"
)

var _ = Describe("MultiVariables", func() {
	Describe("Get", func() {
		It("return no value and not found if there are no sources", func() {
			val, found, err := NewMultiVars(nil).Get(VariableDefinition{})
			Expect(val).To(BeNil())
			Expect(found).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})

		It("return no value and not found if variable is not found in any of the sources", func() {
			vars1 := StaticVariables{"key1": "val"}
			vars2 := StaticVariables{"key2": "val"}
			vars := NewMultiVars([]Variables{vars1, vars2})

			val, found, err := vars.Get(VariableDefinition{Name: "key3"})
			Expect(val).To(BeNil())
			Expect(found).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})

		It("return error as soon as one source fails", func() {
			vars1 := StaticVariables{"key1": "val"}
			vars2 := &FakeVariables{GetErr: errors.New("fake-err")}
			vars := NewMultiVars([]Variables{vars1, vars2})

			val, found, err := vars.Get(VariableDefinition{Name: "key3"})
			Expect(val).To(BeNil())
			Expect(found).To(BeFalse())
			Expect(err).To(Equal(errors.New("fake-err")))
		})

		It("return found value as soon as one source succeeds", func() {
			vars1 := &FakeVariables{}
			vars2 := StaticVariables{"key2": "val"}
			vars3 := &FakeVariables{GetErr: errors.New("fake-err")}
			vars := NewMultiVars([]Variables{vars1, vars2, vars3})

			val, found, err := vars.Get(VariableDefinition{Name: "key2"})
			Expect(val).To(Equal("val"))
			Expect(found).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())

			// Didn't get past second variables
			Expect(vars1.GetCallCount).To(Equal(1))
			Expect(vars3.GetCallCount).To(Equal(0))
		})

		It("sends full variable definition to each tried source", func() {
			vars1 := &FakeVariables{}
			vars2 := StaticVariables{"key2": "val"}
			vars := NewMultiVars([]Variables{vars1, vars2})

			val, found, err := vars.Get(VariableDefinition{Name: "key2", Type: "type", Options: "opts"})
			Expect(val).To(Equal("val"))
			Expect(found).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())

			Expect(vars1.GetVarDef).To(Equal(VariableDefinition{Name: "key2", Type: "type", Options: "opts"}))
		})
	})
})
