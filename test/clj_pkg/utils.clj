(ns clj-pkg.utils
  (:require [clj-pkg.auth :as auth]
            [hato.client :as client]
            [ring.adapter.jetty :as jetty]
            [clojure.tools.logging :as log]))

(def login-port 8981)
(def auth-port 8982)

(defmacro with-api-server [handler & body]
  `(let [server# (jetty/run-jetty ~handler {:port login-port :join? false})]
     (try
       (log/info "start server")
       ~@body
       (finally
         (.stop server#)
         (log/info "stop server")))))

(defmacro with-dev-server [auth-opts & body]
  `(let [dev-server# (auth/run-dev-oauth2 ~auth-opts)]
     (try
       (log/info "start dev server")
       ~@body
       (finally
         (auth/stop-dev-oauth2 dev-server#)
         (log/info "stop dev server")))))

(def ^:dynamic *http-client*)

(defn create-http-client [] (client/build-http-client {:connect-timeout 5000
                                                       :redirect-policy :always
                                                       :cookie-policy   :all}))

(defmacro with-http-client [& body]
  `(binding [*http-client* (create-http-client)]
     (do ~@body)))

(defn client-get [url]
  (when-not (bound? (var *http-client*))
    (throw (Exception. "`client-get` called outside `with-http-client` without http-client specified")))
  (client/get url {:http-client       *http-client*
                   :throw-exceptions? false
                   :as                :json
                   :coerce            :always}))