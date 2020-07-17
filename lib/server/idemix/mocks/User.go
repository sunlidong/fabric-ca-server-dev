// Code generated by mockery v1.0.0. DO NOT EDIT.
package mocks

import api "caserver/api"
import mock "github.com/stretchr/testify/mock"

// User is an autogenerated mock type for the User type
type User struct {
	mock.Mock
}

// GetAffiliationPath provides a mock function with given fields:
func (_m *User) GetAffiliationPath() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// GetAttribute provides a mock function with given fields: name
func (_m *User) GetAttribute(name string) (*api.Attribute, error) {
	ret := _m.Called(name)

	var r0 *api.Attribute
	if rf, ok := ret.Get(0).(func(string) *api.Attribute); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.Attribute)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAttributes provides a mock function with given fields: attrNames
func (_m *User) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	ret := _m.Called(attrNames)

	var r0 []api.Attribute
	if rf, ok := ret.Get(0).(func([]string) []api.Attribute); ok {
		r0 = rf(attrNames)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.Attribute)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(attrNames)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetFailedLoginAttempts provides a mock function with given fields:
func (_m *User) GetFailedLoginAttempts() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// GetLevel provides a mock function with given fields:
func (_m *User) GetLevel() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// GetMaxEnrollments provides a mock function with given fields:
func (_m *User) GetMaxEnrollments() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// GetName provides a mock function with given fields:
func (_m *User) GetName() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetType provides a mock function with given fields:
func (_m *User) GetType() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// IncrementIncorrectPasswordAttempts provides a mock function with given fields:
func (_m *User) IncrementIncorrectPasswordAttempts() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IsRevoked provides a mock function with given fields:
func (_m *User) IsRevoked() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Login provides a mock function with given fields: password, caMaxEnrollment
func (_m *User) Login(password string, caMaxEnrollment int) error {
	ret := _m.Called(password, caMaxEnrollment)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, int) error); ok {
		r0 = rf(password, caMaxEnrollment)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LoginComplete provides a mock function with given fields:
func (_m *User) LoginComplete() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ModifyAttributes provides a mock function with given fields: attrs
func (_m *User) ModifyAttributes(attrs []api.Attribute) error {
	ret := _m.Called(attrs)

	var r0 error
	if rf, ok := ret.Get(0).(func([]api.Attribute) error); ok {
		r0 = rf(attrs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Revoke provides a mock function with given fields:
func (_m *User) Revoke() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SetLevel provides a mock function with given fields: level
func (_m *User) SetLevel(level int) error {
	ret := _m.Called(level)

	var r0 error
	if rf, ok := ret.Get(0).(func(int) error); ok {
		r0 = rf(level)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
