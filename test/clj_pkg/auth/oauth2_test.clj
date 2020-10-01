(ns clj-pkg.auth.oauth2-test
  (:require [clojure.test :refer [deftest is use-fixtures]]
            [clj-pkg.auth :as auth]
            [clojure.data.json :as json]
            [ring.adapter.jetty :as jetty]
            [hato.client :as client]
            [ring.middleware.cookies :as cookies]
            [ring.middleware.json :as json-mw]
            [clojure.tools.logging :as log]
            [ring.util.response :as resp]
            [ring.middleware.params :as params]
            [clojure.string :as string]
            [clj-pkg.auth.providers :as providers]))

(def login-port 8981)
(def auth-port 8982)

(def http-client (client/build-http-client {:connect-timeout 5000
                                            :redirect-policy :always
                                            :cookie-policy   :all}))

(defn oauth2-handler [{:keys [request-method uri headers query-params]}]
  (log/debugf "[MOCK OAUTH2] request %s %s %s" request-method uri headers)
  (case uri
    "/login/oauth/authorize" (let [{:strs [state scope]} query-params]
                               (resp/redirect (format "http://127.0.0.1:%s/callback?code=aqZmjVmOWI&state=%s&scope=%s" login-port state scope) 302))
    "/login/oauth/access_token" (resp/response (json/write-str {:access_token "aqZmjVmOWIaqZmjVmOWI",
                                                                :expires_in   3599,
                                                                :scope        "https://www.googleapis.com/auth/userinfo.profile",
                                                                :token_type   "Bearer",
                                                                :id_token     "aqZmjVmOWIaqZmjVmOWIaqZmjVmOWI"}))
    "/user" (resp/response (json/write-str {:id      123
                                            :name    "Name"
                                            :picture "http://google.com/avatar.png"}))))

(defn add-to-req [handler kw provider]
  (fn [req] (handler (assoc req kw provider))))

(deftest oauth2-test
  (let [provider {:name      "mock"
                  :endpoints {:auth-url  (format "http://127.0.0.1:%d/login/oauth/authorize" auth-port)
                              :token-url (format "http://127.0.0.1:%d/login/oauth/access_token" auth-port)
                              :info-url  (format "http://127.0.0.1:%d/user" auth-port)}
                  :scopes    ["user:email"]
                  :map-user  (fn [{:keys [id name picture]}]
                               {:id (str "mock_" id) :name name :picture picture})}
        params {:client-id "cid" :client-secret "csecret"}
        handler (-> providers/handler
                    (add-to-req :provider (merge params provider))
                    (add-to-req :auth-opts {:secret "123"})
                    (params/wrap-params)
                    (cookies/wrap-cookies)
                    (json-mw/wrap-json-response))
        server (jetty/run-jetty handler {:port login-port :join? false})
        oauth2-server (jetty/run-jetty (-> oauth2-handler
                                           (params/wrap-params)) {:port auth-port :join? false})]
    (try
      (let [{:keys [headers body]} (client/get "http://127.0.0.1:8981/login" {:http-client http-client
                                                                              :as          :json})]
        (is (= body
               {:id      123
                :name    "Name"
                :picture "http://google.com/avatar.png"}))
        (is (true? (-> (get headers "set-cookie") first (string/starts-with? "JWT="))))
        (is (true? (-> (get headers "set-cookie") second (string/starts-with? "XSRF-TOKEN=")))))
      (finally
        (.stop server)
        (.stop oauth2-server)))))