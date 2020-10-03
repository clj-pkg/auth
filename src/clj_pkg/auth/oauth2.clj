(ns clj-pkg.auth.oauth2
  (:require [clojure.tools.logging :as log]
            [clj-pkg.auth.token :refer [unix-time-plus-minutes] :as token]
            [clj-pkg.railway :refer [=>] :as rw]
            [hato.client :as client]
            [camel-snake-kebab.core :refer [->kebab-case-keyword ->snake_case_keyword]]
            [camel-snake-kebab.extras :as cske]
            [clojure.string :as string]
            [ring.util.request :as req]
            [ring.util.codec :as codec]
            [ring.util.response :as resp])
  (:import (java.util UUID)))

(defn random-string []
  (.toString (UUID/randomUUID)))

(defn- create-redirect-url [req]
  (string/join "/" (-> req
                       (dissoc :query-string)
                       (req/request-url)
                       (string/split #"/")
                       (drop-last)
                       (concat ["callback"]))))

(defn user-info [access-token {:keys [endpoints]}]
  (->> {:query-params {:access_token access-token}
        :as           :json}
       (client/get (:info-url endpoints))
       :body
       (cske/transform-keys ->kebab-case-keyword)))

(defn exchange [code {:keys [client-id client-secret endpoints]}]
  (let [redirect-url (:redirect-url endpoints)
        access-token-url (:token-url endpoints)]
    (->> {:form-params {:code          code
                        :grant_type    "authorization_code"
                        :client_id     client-id
                        :client_secret client-secret
                        :redirect_uri  redirect-url}
          :accept      :json
          :as          :json}
         (client/post access-token-url)
         :body
         (cske/transform-keys ->kebab-case-keyword)
         :access-token)))

(defn build-login-url [req state provider]
  (let [client-id (-> provider :client-id)
        scopes (string/join " " (-> provider :scopes))
        authorize-url (-> provider :endpoints :auth-url)
        redirect-url (or (-> provider :endpoints :redirect-url) (create-redirect-url req))]
    (format "%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s" authorize-url client-id redirect-url scopes state)))

(defn- create-claims [state from]
  {:id         state
   :expires-at (unix-time-plus-minutes 30)
   :not-before (unix-time-plus-minutes -1)
   :handshake  {:state state
                :from  from}})

(defn- get-return-url-parameter [req]
  (-> req :query-params (get "from")))

(defn clean-address [params]
  "Ensure (params :address) is present"
  (if (empty? (params :address))
    [nil "Please enter your address"]
    [params nil]))

(defn clean-contact [params]
  (=> params
      clean-address))

(clean-contact {:address "123 Fake St."})

(defn validate-code [req]
  (if-let [{:strs [code]} (-> req :query-params)]
    [(assoc req :code code) nil]
    [nil "no authorization code"]))

(defn validate-claims [req]
  (if-let [claims (token/get-claims req)]
    [(assoc req :claims claims) nil]
    [nil "failed to get token"]))

(defn validate-state [{:keys [claims] :as req}]
  (let [{:strs [state]} (-> req :query-params)]
    (if (= state (-> claims :handshake :state))
      [req nil]
      [nil "invalid handshake token"])))

(defn build-redirect-url [req]
  (->> req
       create-redirect-url
       (assoc-in req [:provider :endpoints :redirect-url])
       rw/success))

(defn retrieve-access-token [{:keys [code provider] :as req}]
  (let [tok (exchange code provider)]
    [(assoc req :access-token tok)]))

(defn retrieve-user-info [{:keys [access-token provider] :as req}]
  (let [map-user-fn (or (:map-user-fn provider) identity)]
    (->> provider
         (user-info access-token)
         (map-user-fn)
         (assoc req :user-info)
         (rw/success))))

(defn create-auth-cookies [{:keys [claims user-info auth-opts] :as req}]
  (-> req
      (assoc :redirect-url (-> claims :handshake :from))
      (assoc :cookies (token/set-cookies auth-opts {:id           (random-string)
                                                    :issuer       (:issuer auth-opts)
                                                    :user         user-info
                                                    :session-only (:session-only claims)}))
      (rw/success)))

;GET /login?from=redirect-back-url&session=1
(defn login-handler [{:keys [auth-opts provider] :as req}]
  (log/debugf "login with provider %s" (:name provider))
  (let [state (random-string)
        claims (->> req
                    (get-return-url-parameter)
                    (create-claims state))
        login-url (build-login-url req state provider)]
    (log/debugf "login url %s, claims=%s" login-url claims)
    {:status  302
     :cookies (token/set-cookies auth-opts claims)
     :headers {"Location" login-url}}))

; GET /{provider}/callback
(defn auth-handler [req]
  (try
    (let [[{:keys [redirect-url cookies user-info]} err] (=> req
                                                             validate-code
                                                             validate-claims
                                                             validate-state
                                                             build-redirect-url
                                                             retrieve-access-token
                                                             retrieve-user-info
                                                             create-auth-cookies)]
      (cond
        (not (nil? err)) (resp/bad-request {:error err})
        (not (nil? redirect-url)) {:status  302
                                   :cookies cookies
                                   :headers {"Location" redirect-url}}
        :else {:status  200
               :cookies cookies
               :body    user-info}))
    (catch Exception e
      {:status  200
       :body    "Internal server error"})))

; GET /{provider}/logout
(defn logout-handler [_]
  (log/debug "logout")
  {:status  200
   :cookies (token/reset)})
