(ns simple-authentication.core
  (:require [simple-authentication.bcrypt :as bcrypt]
            [ring.util.response :as response]))

(defn- login-request? [login-uri request]
  "Returns true if the request goes to the login-url and the request method is POST."
  (and (= login-uri
          (:uri request))
       (= (:request-method request)
          :post)))

(defn- logout-request? [logout-uri request]
  "Returns true if the request goes to the logout-url and the request method is POST."
  (and (= logout-uri
          (:uri request))
       (= (:request-method request)
          :post)))

(defn- handle-login [login-uri login-success-uri query-fn {{:keys [login password]} :params}]
  "Query for the user with the query-fn. If the credentials match then return a response with a redirect to the login-success-uri with the user stored in the session map with the password removed. Otherwise redirect to the login-uri."
  (let [user (query-fn login)]
    (if (bcrypt/plain-text-matches-hashed? password (:password user))
      (let [response (response/redirect login-success-uri)]
        (assoc response :session (dissoc user :password)))
      (response/redirect login-uri))))

(defn- handle-logout [logout-success-uri request]
  "Called when the request is a post to the logout-uri. It returns a response with the session set to nil."
  (let [response (response/redirect logout-success-uri)]
    (assoc response :session nil)))

(defn authentication [app {login-uri :login-uri
                           login-success-uri :login-success-uri
                           logout-uri :logout-uri
                           logout-success-uri :logout-success-uri
                           query-fn :query-fn}]
  "Middleware for handling all authentication requests. When it is a login request, it calls the query-fn with the login passed in from the form.

The query-fn should return a map containing the user from somewhere like a database. The user map is then checked against the password submitted by the form.

If the credentials are valid, the user is redirected to the login-success-uri. If not, they get redirected back to the login-uri."
  (fn [request]
    (cond
     (login-request? login-uri request)
     (handle-login login-uri login-success-uri query-fn request)
     (logout-request? logout-uri request)
     (handle-logout logout-success-uri request)
     :else (app request))))