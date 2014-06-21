(ns simple-authentication.core
  (:require [simple-authentication.bcrypt :as bcrypt]
            [ring.util.response :as response]))

(defn- request-matches-uri-and-method? [uri method request]
  "Returns true if the request goes to the uri and the request
method matches the request's method."
  (and (= uri (:uri request))
       (= method (:request-method request))))

(defn- login-request? [login-uri request]
  "Returns true if the request goes to the login-url and the request
method is POST."
  (request-matches-uri-and-method? login-uri :post request))

(defn- logout-request? [logout-uri request]
  "Returns true if the request goes to the logout-url and the request
method is GET."
  (request-matches-uri-and-method? logout-uri :get request))

(defn- handle-login [login-uri login-success-uri query-fn {{:keys [login password]} :params}]
  "Query for the user with the query-fn. If the credentials match then
return a response with a redirect to the login-success-uri with the
user stored in the session map with the password removed. Otherwise
redirect to the login-uri. If the credentials don't match (if query-fn
returns nil) then returns a response with a redirect to the login-uri
with the login used in the url."
  (let [user (query-fn login)]
    (if (and user
             (bcrypt/plain-text-matches-hashed? password (:password user)))
      (let [response (response/redirect login-success-uri)]
        (assoc response :session (dissoc user :password)))
      (response/redirect (str login-uri "?login=" login)))))

(defn- handle-logout [logout-success-uri request]
  "Called when the request is a post to the logout-uri. It returns a
response with the session set to nil."
  (let [response (response/redirect logout-success-uri)]
    (assoc response :session nil)))

(defn authentication [handler {login-uri :login-uri
                               login-success-uri :login-success-uri
                               logout-uri :logout-uri
                               logout-success-uri :logout-success-uri
                               query-fn :query-fn}]
  "Middleware for handling all authentication requests. When it is a
login request, it calls the query-fn with the login passed in from
the form.

The query-fn should return a map containing the user from somewhere
like a database. The user map is then checked against the password
submitted by the form. If the credentials are valid, the user is
redirected to the login-success-uri. If not, they get redirected back
to the login-uri.

When it is a logout request it sets the session to nil and redirects
to the logout-success-uri"
  (fn [request]
    (cond
     (login-request? login-uri request)
     (handle-login login-uri login-success-uri query-fn request)
     (logout-request? logout-uri request)
     (handle-logout logout-success-uri request)
     :else (handler request))))

(defn login-required [{login-uri :login-uri} handler]
  "Middleware that redirects to the login-uri for the handler if the
user is not logged in.

Example usage: (login-required {:login-uri \"/login\"}
submissions/login-required-routes)

A good pattern is using partial like so: (def login-required (partial
simple-auth/login-required {:login-uri \"/login\"}))

That way you don't have to explicity pass in the login uri every time."
  (fn [request]
    (let [response (handler request)]
      (if (and (empty? (:session request))
               response)
        (response/redirect login-uri)
        response))))
