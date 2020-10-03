(ns clj-pkg.auth
  (:require [clojure.string :as string]
            [camel-snake-kebab.core :refer [->kebab-case-keyword ->snake_case_keyword]]
            [clojure.tools.logging :as log]
            [clojure.spec.alpha :as s]
            [ring.util.response :as resp]
            [clj-pkg.auth.token :as token]
            ;[clj-pkg.railway :refer [=>]]
            [clj-pkg.auth.providers :as prov]
            [clj-pkg.auth.dev-provider :as dev-provider]))

(defn unauthorized [body]
  {:status 401
   :body   body})

(defn user-handler [req]
  (if-let [claims (token/get-claims req)]
    (resp/response (-> claims :user))
    (unauthorized {:error "Unauthorized"})))

(defn deep-merge [a & maps]
  (if (map? a)
    (apply merge-with deep-merge a maps)
    (apply merge-with deep-merge maps)))

(defn handlers [options]
  (let [prov-data (-> prov/data (select-keys (-> options :providers keys)))
        providers (deep-merge prov-data (:providers options))
        opts (dissoc options :providers)]                   ; todo initialize
    (fn [{:keys [uri] :as req}]
      (let [parts (string/split uri #"/")
            provider-kw (-> parts drop-last last keyword)
            req (-> req
                    (assoc :provider (get providers provider-kw))
                    (assoc :auth-opts opts))]
        (cond
          (= (last parts) "list") (resp/response (keys providers))
          (= (last parts) "user") (user-handler req)
          (= (last parts) "logout") (prov/handler (assoc req :provider (first providers)))
          (contains? providers provider-kw) (prov/handler req)
          :else (resp/bad-request {:error "provider not supported"}))))))

(defn run-dev-oauth2
  "DevAuth makes dev oauth2 server, for testing and development only!"
  [{:keys [providers]}]
  (dev-provider/run (:dev providers)))

(defn stop-dev-oauth2
  [server]
  (dev-provider/stop server))


;(defn validate-claims [req]
;  (if-let [claims (token/get-claims req)]
;    [{:claims claims} nil]
;    [nil "failed to get token"]))
;
;(defn middleware2 []
;  (fn [req]
;    (=> req
;        validate-claims))
;  )

(defn refresh-token [auth-opts claims]
  (token/set-cookies auth-opts (dissoc claims :expires-at)))

(defn middleware
  "Middleware used in routes that require authentication. If request is not
   authenticated a 401 not authorized response will be returned"
  [options]
  (fn [handler]
    (fn [req]
      (if-let [claims (token/get-claims (assoc req :auth-opts options))]
        (if-let [user (:user claims)]
          (let [validator-fn (:validator options)]
            (if (or (nil? validator-fn) (validator-fn "tkn-str" claims))
              (if (token/expired? claims)
                (let [cookies (refresh-token options claims)
                      resp (handler (assoc req :user user))]
                  (assoc resp :cookies cookies))
                (handler (assoc req :user user)))
              (do
                (log/infof "user %s/%s blocked" (:name user) (:id user))
                (assoc (unauthorized {:error "Unauthorized"}) :cookies (token/reset)))))
          (unauthorized {:error "Unauthorized"}))
        (unauthorized {:error "Unauthorized"})))))

(defn updated-user-middleware [user-updater-fn]
  (fn [handler]
    (fn [req]
      (handler (-> req :user user-updater-fn (assoc req :user))))))