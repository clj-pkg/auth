(ns clj-pkg.auth.token
  (:require [clj-pkg.jwt :as jwt]
            [clojure.tools.logging :as log])
  (:import (java.security MessageDigest)))

(def default-jwt-cookie-name "JWT")
(def default-jwt-header-key "X-JWT")
(def default-xsrf-cookie-name "XSRF-TOKEN")
(def default-xsrf-header-key "X-XSRF-TOKEN")
(def default-issuer "clj-pkg/auth")

(def default-token-duration (* 60 15))                      ; 15 minutes
(def default-cookie-duration (* 60 60 24 31))               ; 1 month

(defn set-cookies [auth-opts claims]
  (let [cookie-duration (or (:cookie-duration auth-opts) default-cookie-duration) ; TODO set to max-age if not session only and handshake == nil
        claims (merge {:issuer default-issuer} claims)
        jwt-token (jwt/sign (jwt/jwt :hs256 claims) (:secret auth-opts))]

    {default-jwt-cookie-name  {:value     jwt-token
                               :http-only true
                               :path      "/"
                               :secure    false}
     default-xsrf-cookie-name {:value     (:id claims)
                               :http-only false
                               :path      "/"
                               :secure    false}}))

(defn get-claims [{:keys [auth-opts cookies]}]
  (try
    (let [token (-> cookies (get default-jwt-cookie-name) :value jwt/str->jwt)]
      (if (jwt/verify token (:secret auth-opts))
        (:claims token)
        (throw (IllegalArgumentException. "token is invalid"))))
    (catch Exception e
      (log/error e)
      nil)))

(defn reset []
  {default-jwt-cookie-name  {:value     ""
                             :http-only false
                             :path      "/"
                             :max-age   -1
                             :secure    false}
   default-xsrf-cookie-name {:value     ""
                             :http-only false
                             :path      "/"
                             :max-age   -1
                             :secure    false}})

(defn- sha1-str [s]
  (->> (-> "sha1"
           MessageDigest/getInstance
           (.digest (.getBytes s)))
       (map #(.substring
               (Integer/toString
                 (+ (bit-and % 0xff) 0x100) 16) 1))
       (apply str)))

(defn hash-id [id]
  (sha1-str id))