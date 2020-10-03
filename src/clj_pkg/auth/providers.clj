(ns clj-pkg.auth.providers
  (:require [clj-pkg.auth.token :as token]
            [clj-pkg.auth.oauth2 :as oauth2]
            [clojure.string :refer [ends-with?]]
            [ring.util.response :as resp]))

(def data
  {:google {:name        :google
            :type        :oauth2
            :endpoints   {:auth-url  "https://accounts.google.com/o/oauth2/auth"
                          :token-url "https://oauth2.googleapis.com/token"
                          :info-url  "https://www.googleapis.com/oauth2/v3/userinfo"}
            :scopes      ["https://www.googleapis.com/auth/userinfo.profile"]
            :map-user-fn (fn [{:keys [sub name picture]}]
                           {:id      (str "google_" (token/hash-id sub))
                            :name    (or name "noname")
                            :picture picture})}

   :github {:name        :github
            :type        :oauth2
            :endpoints   {:auth-url  "https://github.com/login/oauth/authorize"
                          :token-url "https://github.com/login/oauth/access_token"
                          :info-url  "https://api.github.com/user"}
            :scopes      []
            :map-user-fn (fn [{:keys [login name avatar-url]}]
                           {:id      (str "github_" (token/hash-id login))
                            :name    (or name login)
                            :picture avatar-url})}

   :dev    {:name          :dev
            :client-id     ""
            :client-secret ""
            :automatic?    true
            :endpoints     {:auth-url  "http://127.0.0.1:8084/login/oauth/authorize"
                            :token-url "http://127.0.0.1:8084/login/oauth/access_token"
                            :info-url  "http://127.0.0.1:8084/user"}
            :map-user-fn   (fn [{:keys [id name picture]}]
                             {:id      (str "dev_" (token/hash-id id))
                              :name    name
                              :picture picture})}})

(defn handler [{:keys [uri provider] :as req}]
  (if provider
    (cond
      (ends-with? uri "/login") (oauth2/login-handler req)
      (ends-with? uri "/callback") (oauth2/auth-handler req)
      (ends-with? uri "/logout") (oauth2/logout-handler req)
      :else (resp/not-found nil))
    (resp/bad-request {:error "providers not defined"})))
