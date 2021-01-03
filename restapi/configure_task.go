// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	_ "github.com/go-sql-driver/mysql"

	"V11/models"
	"V11/restapi/operations"
	"V11/restapi/operations/users"
)

var tokenGenrated string
var JWTSigningKey = []byte("thisIstheSuperSecretKey")

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = "sam minhas"
	//claims["exp"]= time.Now().Add(time.Minute * 30).unix()

	tokenString, err := token.SignedString(JWTSigningKey)

	if err != nil {
		fmt.Errorf("Something has gone: %s", err.Error())
		return " ", err
	}
	return tokenString, nil
}

func verify_jwt(tokenString string) (bool, error) {

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return JWTSigningKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["foo"], claims["nbf"])
	} else {
		fmt.Println(err)
	}
	return true, nil
}

//go:generate swagger generate server --target ../../AssessmentTaskV7 --name TaskV7 --spec ../swagger.yml --principal interface{}
//////////////////////////definig the stuct///////////////////////////////////////////////////////////////////
type UsersInfo struct {
	Name     string
	Email    string
	Password string
}

//go:generate swagger generate server --target ../../V11 --name Task --spec ../swagger.yml --principal interface{}

func configureFlags(api *operations.TaskAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.TaskAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	api.UsersRegisterUserHandler = users.RegisterUserHandlerFunc(func(params users.RegisterUserParams) middleware.Responder {
		// connect the database
		usersDb, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/taskDb")
		if err != nil {
			return users.NewRegisterUserBadRequest()
		}
		defer usersDb.Close()

		// declaring a variable with the data type struct

		var postedJSONData UsersInfo

		// now saving the data in the  params in to that the varivable

		postedJSONData.Name = *params.RegisterUserBody.Name
		postedJSONData.Email = *params.RegisterUserBody.Email
		postedJSONData.Password = *params.RegisterUserBody.Password

		// now saving the data into the database

		var ins *sql.Stmt

		ins, err = usersDb.Prepare("INSERT INTO Users(Name , Email , Password) VALUES (?,?,?);")
		if err != nil {
			return users.NewRegisterUserBadRequest()
		}
		defer ins.Close()

		_, err = ins.Exec(postedJSONData.Name, postedJSONData.Email, postedJSONData.Password)
		if err != nil {
			return users.NewRegisterUserBadRequest()
		}

		return users.NewRegisterUserOK().WithPayload(&models.SuccessResponseDefinition{Message: "User's Registration Successful"})
	})
	api.UsersUpdateUserHandler = users.UpdateUserHandlerFunc(func(params users.UpdateUserParams) middleware.Responder {
		//saving the data in body of the request to the varibles for the updating []
		nameInBody := *params.UpdateUserBody.Name
		passwordInBody := *params.UpdateUserBody.Password
		emailAsKey := *params.UpdateUserBody.Email
		tokenFoundInBody := *params.UpdateUserBody.JwtToken

		_, err := verify_jwt(tokenFoundInBody)
		if err != nil {
			// retunr here
		}

		// connect the database
		usersDb, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/taskDb")
		if err != nil {
			panic(err.Error())
		}
		defer usersDb.Close()
		// upfdating the database
		update, err := usersDb.Prepare("UPDATE `taskDb`. `Users` SET `Name` = ? , `Password` = ? WHERE (`Email`= ?);")

		if err != nil {
			panic(err.Error())
		}

		update.Exec(nameInBody, passwordInBody, emailAsKey)

		return users.NewUpdateUserOK()
	})
	api.UsersLoginUserHandler = users.LoginUserHandlerFunc(func(params users.LoginUserParams) middleware.Responder {
		EmailInBody := *params.LoginUserBody.Email
		PasswordInBody := *params.LoginUserBody.Password

		// connecting the database

		userDb, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/taskDb")

		if err != nil {
			return users.NewLoginUserBadRequest()
		}

		defer userDb.Close()

		// getting the data from the database table and compare it with

		getData, err := userDb.Query("SELECT * FROM `taskDb`.`Users`")
		if err != nil {
			return users.NewLoginUserBadRequest()
		}
		for getData.Next() {
			var (
				Name     string
				Email    string
				Password string
			)
			getData.Scan(&Name, &Email, &Password)

			if Email == EmailInBody && Password == PasswordInBody {
				tokenString, err := GenerateJWT()
				if err != nil {
					fmt.Println("there is an error while genrating the taken")
					return users.NewLoginUserBadRequest()
				}
				fmt.Println(tokenString)
				tokenGenrated = tokenString
				return users.NewLoginUserOK().WithPayload(&models.LoginSuccessResponseDefinition{Token: tokenGenrated})
			}

		}

		return users.NewLoginUserBadRequest()
	})

	if api.UsersRegisterUserHandler == nil {
		api.UsersRegisterUserHandler = users.RegisterUserHandlerFunc(func(params users.RegisterUserParams) middleware.Responder {
			return middleware.NotImplemented("operation users.RegisterUser has not yet been implemented")
		})
	}
	if api.UsersUpdateUserHandler == nil {
		api.UsersUpdateUserHandler = users.UpdateUserHandlerFunc(func(params users.UpdateUserParams) middleware.Responder {
			return middleware.NotImplemented("operation users.UpdateUser has not yet been implemented")
		})
	}
	if api.UsersLoginUserHandler == nil {
		api.UsersLoginUserHandler = users.LoginUserHandlerFunc(func(params users.LoginUserParams) middleware.Responder {
			return middleware.NotImplemented("operation users.LoginUser has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
