(ns clj-pkg.auth.dev-provider
  (:require [clojure.tools.logging :as log]
            [ring.util.response :as resp]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.params :as params]
            [ring.middleware.json :refer [wrap-json-response]]
            [clojure.java.io :as io]
            [clojure.string :as string])
  (:import (org.eclipse.jetty.server Server)))

(def dev-auth-port 8084)
(def user-info (atom {:username "dev-user"}))

(defn oauth2-handler [{:keys [automatic?]}]
  (fn [{:keys [request-method uri headers query-params] :as req}]
    (log/debugf "dev oauth request %s %s %s" request-method uri headers)
    (case uri
      "/login/oauth/authorize" (let [{:strs [state scope redirect_uri]} query-params
                                     url (format "%s?code=aqZmjVmOWI&state=%s&scope=%s" redirect_uri state scope)]
                                 (if automatic?
                                   (resp/redirect url)
                                   (if-let [username (-> req :form-params (get "username"))]
                                     (do (swap! user-info assoc :username username)
                                         (resp/redirect url))
                                     (resp/response (-> "dev-auth.html" io/resource slurp (string/replace #"\$query" (:query-string req)))))))
      "/login/oauth/access_token" (resp/response {:access_token "aqZmjVmOWIaqZmjVmOWI",
                                                  :expires_in   3599,
                                                  :scope        "https://www.googleapis.com/auth/userinfo.profile",
                                                  :token_type   "Bearer",
                                                  :id_token     "aqZmjVmOWIaqZmjVmOWIaqZmjVmOWI"})
      "/user" (resp/response {:id      123
                              :name    (:username @user-info)
                              :picture (format "http://127.0.0.1:%s/avatar?user=%s" dev-auth-port (:username @user-info))})
      "/avatar" (resp/response nil))))                      ; TODO implement avatar

(defn run [provider]
  (log/infof "[INFO] run local oauth2 dev server on %d, redirect url=%s" dev-auth-port :redirect-url)
  (jetty/run-jetty (-> provider
                       (oauth2-handler)
                       (params/wrap-params)
                       (wrap-json-response)) {:port dev-auth-port :join? false}))

(defn stop [^Server server]
  (log/info "shutdown oauth2 dev server")
  (.stop server))