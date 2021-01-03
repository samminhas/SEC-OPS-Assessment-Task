// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SuccessResponseDefinition success response definition
//
// swagger:model SuccessResponseDefinition
type SuccessResponseDefinition struct {

	// message
	Message string `json:"message,omitempty"`
}

// Validate validates this success response definition
func (m *SuccessResponseDefinition) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SuccessResponseDefinition) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SuccessResponseDefinition) UnmarshalBinary(b []byte) error {
	var res SuccessResponseDefinition
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
