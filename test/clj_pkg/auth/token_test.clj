(ns clj-pkg.auth.token-test
  (:require [clojure.test :refer [deftest is]])
  (:require [clj-pkg.auth.token :refer [hash-id]]))

(deftest hash-id-test
  (is (= (hash-id "123") "40bd001563085fc35165329ea1ff5c5ecbdbbeef")))
