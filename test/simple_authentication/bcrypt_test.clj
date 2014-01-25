(ns simple-authentication.bcrypt-test
  (:require [clojure.test :refer :all]
            [simple-authentication.bcrypt :refer :all]))

(deftest password
  (is (= true
         (plain-text-matches-hashed? "password"
                                     (hash-password "password")))))