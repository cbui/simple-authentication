(ns simple-authentication.core
  (:require [simple-authentication.bcrypt :as bcrypt]
            [ring.util.response :as response]))

(defn- login-request? [login-url request]
  "Returns true if the request goes to the login-url and the request method is POST."
  (and (= login-url
          (:uri request))
       (= (:request-method request)
          :post)))

(defn- credentials-valid? [query-fn {{:keys [login password]} :params}]
  "Checks the credentials returned from calling the query-fn with the login and the submitted credentials from the request. Returns true if the plaintext password matches the hashed password."
  (when-let [user (query-fn login)]
    (bcrypt/check-password password (:password user))))

(defn- handle-login [login-uri login-success-uri query-fn request]
  "If the request is a post to the login-uri then it checks the credentials returned from the query-fn and the form params in the request. It returns a respones that redirects the user to the login uri if it is a failure, or redirects the user to the login url."
  (when (login-request? login-uri request)
    (if (credentials-valid? query-fn request)
      (response/redirect login-success-uri)
      (response/redirect login-uri))))

(defn authentication [app {login-uri :login-uri
                           login-success-uri :login-success-uri
                           query-fn :query-fn}]
  "Middleware for handling all authentication requests. When it is a login request, it calls the query-fn with the login passed in from the form.

The query-fn should return a map containing the user from somewhere like a database. The user map is then checked against the password submitted by the form.

If the credentials are valid, the user is redirected to the login-success-uri. If not, they get redirected back to the login-uri."
  (fn [request]
    (if-let [response (handle-login login-uri login-success-uri query-fn request)]
      response
      (app request))))