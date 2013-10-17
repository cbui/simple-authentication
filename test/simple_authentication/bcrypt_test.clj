(ns simple-authentication.bcrypt-test
  (:require [clojure.test :refer :all]
            [simple-authentication.bcrypt :refer :all]))

(deftest password
  (is (= true
         (check-password "password"
          (hash-password "password")))))