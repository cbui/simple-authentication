# simple-authentication

Just simple user authentication for Clojure Ring web applications. Does a lot less than friend while being a lot easier to use.

## Usage

`[com.christopherdbui/simple-authentication "0.1.3"]`

I based it off of friend a bit so the usage is a little similar.

Here's a sample project that does login simply:

    ;; project.clj
    (defproject simple-login "0.1.0-SNAPSHOT"
        :description "A simple application to show the simple-authentication library."
        :license {:name "Eclipse Public License"
                  :url "http://www.eclipse.org/legal/epl-v10.html"}
        :dependencies [[org.clojure/clojure "1.5.1"]
                       [com.christopherdbui/simple-authentication "0.1.3"]
                       [hiccup "1.0.4"]                 
                       [compojure "1.1.5"]
                       [http-kit "2.1.5"]])
         
```              
;; src/simple_login/core.clj
(ns simple-login.core
  (:require [compojure.core :as compojure]
            [compojure.route :as route]
            [compojure.handler :as handler]
            [hiccup.core :as hiccup]
            [org.httpkit.server :as http-kit]
            [simple-authentication.core :as simple-authentication]
            [simple-authentication.bcrypt :as bcrypt]))

(defn login-view [request]
  (hiccup/html
   [:form {:action "/" :method "POST"}
    [:label "Username"]
    [:input {:type "text" :name "login"}]
    [:label "Password"]
    [:input {:type "password" :name "password"}]
    [:input {:type "submit"}]]
   [:form {:action "/logout" :method "POST"}
    [:input {:type "submit" :value "Logout"}]
    (:session request)]))

(def users
  {"chris"
   {:username "chris" :password (bcrypt/hash-password "password")}})

(defn query-fn [login]
  (users login))

(compojure/defroutes app-routes
  (compojure/GET "/" request (login-view request))
  (route/not-found "Not Found"))

(def secured-routes
  (simple-authentication/authentication app-routes {:login-uri "/login"
                                                    :login-success-uri "/"
                                                    :logout-uri "/logout"
                                                    :logout-success-uri "/"
                                                    :query-fn query-fn}))

(def app
  (-> secured-routes
      (handler/site)))

(defn -main []
  (defonce web-server (http-kit/run-server #'app {:port 8080 :join? false})))

```

First, you're going to want to define your app's routes. Then you apply the middleware to the routes and pass in the required options.

`:login-uri` is the uri that your login form is going to post to.
`:login-success-uri` is the uri that your login form is going to redirect to when a successful login occurs.
`:logout-uri` is the uri that logs the user out when they visit it.
`:logout-success-uri` is the uri that the logged out user is redirect to after they're logged out.
`:query-fn` is the function that querys your data store and returns a map that contains a :password key with the user's bcrypted password. The function that checks if the password matches the form submitted password returns the map without the password key. It gets called with the login that was submitted by the form.

When you store passwords in the database or somewhere, you're going to want to use the hash-password function in the bcrypt namespace.

The query function in the sample project is just to an in memory datastore. You're not going to want to do this in a real application.

The next thing you want to do is define your app with your secured routes in front of the other middleware. You're have to use compojure's site middleware in for this to work.

Your login form is going to need to submit a "login" and a "password". I purposefully named it login instead of email or username because it prevents confusion incase you had a login scheme with an email or a username.

## License

Copyright © 2014 Christopher Bui

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
