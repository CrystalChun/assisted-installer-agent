// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Bundle bundle
//
// swagger:model bundle
type Bundle struct {

	// Longer human friendly description for the bundle, usually one or more sentences.
	//
	Description string `json:"description,omitempty"`

	// Unique identifier of the bundle, for example `virtualization` or `openshift-ai-nvidia`.
	ID string `json:"id,omitempty"`

	// List of operators associated with the bundle.
	Operators []string `json:"operators"`

	// Short human friendly description for the bundle, usually only a few words, for example `Virtualization` or
	// `OpenShift AI (NVIDIA)`.
	//
	Title string `json:"title,omitempty"`
}

// Validate validates this bundle
func (m *Bundle) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this bundle based on context it is used
func (m *Bundle) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Bundle) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Bundle) UnmarshalBinary(b []byte) error {
	var res Bundle
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
