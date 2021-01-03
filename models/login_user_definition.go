// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// LoginUserDefinition login user definition
//
// swagger:model LoginUserDefinition
type LoginUserDefinition struct {

	// email
	// Required: true
	Email *string `json:"Email"`

	// password
	// Required: true
	Password *string `json:"Password"`
}

// Validate validates this login user definition
func (m *LoginUserDefinition) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePassword(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *LoginUserDefinition) validateEmail(formats strfmt.Registry) error {

	if err := validate.Required("Email", "body", m.Email); err != nil {
		return err
	}

	return nil
}

func (m *LoginUserDefinition) validatePassword(formats strfmt.Registry) error {

	if err := validate.Required("Password", "body", m.Password); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *LoginUserDefinition) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginUserDefinition) UnmarshalBinary(b []byte) error {
	var res LoginUserDefinition
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}