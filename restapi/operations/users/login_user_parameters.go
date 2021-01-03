// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	"V11/models"
)

// NewLoginUserParams creates a new LoginUserParams object
// no default values defined in spec.
func NewLoginUserParams() LoginUserParams {

	return LoginUserParams{}
}

// LoginUserParams contains all the bound params for the login user operation
// typically these are obtained from a http.Request
//
// swagger:parameters loginUser
type LoginUserParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*This is how the body of the login user request body will look like.
	  Required: true
	  In: body
	*/
	LoginUserBody *models.LoginUserDefinition
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewLoginUserParams() beforehand.
func (o *LoginUserParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.LoginUserDefinition
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("loginUserBody", "body", ""))
			} else {
				res = append(res, errors.NewParseError("loginUserBody", "body", "", err))
			}
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.LoginUserBody = &body
			}
		}
	} else {
		res = append(res, errors.Required("loginUserBody", "body", ""))
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
