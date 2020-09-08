(ns clj-pkg.auth-test
  (:require [clojure.test :refer [deftest is]]
            [clj-pkg.auth :as auth]
            [ring.middleware.cookies :as cookies]
            [ring.middleware.json :as json-mw]
            [clojure.string :as string]
            [reitit.ring :as ring]
            [reitit.ring.middleware.parameters :as parameters]
            [clj-pkg.utils :refer [with-http-client with-server client-get]]))

(def auth-params {:google {:name          :google
                           :type          :oauth2
                           :client-id     "12345"
                           :client-secret "6789"
                           :endpoints     {:auth-url     "https://accounts.google.com/o/oauth2/auth"
                                           :token-url    "https://oauth2.googleapis.com/token"
                                           :info-url     "https://www.googleapis.com/oauth2/v3/userinfo"
                                           :redirect-url "http://127.0.0.1:8981/auth/google/callback"}
                           :scopes        ["https://www.googleapis.com/auth/userinfo.profile"]
                           :map-user      (fn [{:keys [id name picture]}]
                                            {:id      "google_id"
                                             :name    (or name "noname")
                                             :picture picture})}
                  :dev    {
                           :client-id     ""
                           :client-secret ""
                           :automatic?    true
                           :redirect-url  "http://127.0.0.1:8981/auth/dev/callback"

                           :endpoints     {:auth-url  "http://127.0.0.1:8084/login/oauth/authorize"
                                           :token-url "http://127.0.0.1:8084/login/oauth/access_token"
                                           :info-url  "http://127.0.0.1:8084/user"}}})

(def cookies-middleware
  {:name ::cookies
   :wrap cookies/wrap-cookies})

(def json-response-middleware
  {:name ::json-response
   :wrap json-mw/wrap-json-response})

(def route-middleware {:data {:middleware [parameters/parameters-middleware
                                           json-response-middleware
                                           cookies-middleware]}})

(def handler (ring/ring-handler
               (ring/router [["/auth/*" (auth/handlers auth-params)]
                             ["/open" {:handler (fn [_] {:status 200 :body {:data "open data"}})}]
                             ["/private" {:middleware [auth/middleware]
                                          :handler    (fn [_] {:status 200 :body {:data "private data"}})}]]
                            route-middleware)))

(deftest ^:integration protected-test
  (with-http-client
    (with-server
      handler

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/open")]
        (is (= status 200))
        (is (= body {:data "open data"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/private")]
        (is (= status 401))
        (is (= body {:error "Unauthorized"})))

      (let [{:keys [status headers body] :as resp} (client-get "http://127.0.0.1:8981/auth/dev/login")]
        (is (= status 200))
        (is (= body {:id 123 :name "Name" :picture "http://127.0.0.1:8084/avatar?user=dev-user"}))
        (is (= 2 (count (get headers "set-cookie"))))
        (is (true? (-> (get headers "set-cookie") first (string/starts-with? "JWT="))))
        (is (true? (-> (get headers "set-cookie") second (string/starts-with? "XSRF-TOKEN=")))))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/private")]
        (is (= status 200))
        (is (= body {:data "private data"}))))))

(deftest ^:integration list-test
  (with-http-client
    (with-server
      handler

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/list")]
        (is (= status 200))
        (is (= body ["google" "dev"]))))))

(deftest ^:integration user-info-test
  (with-http-client
    (with-server
      handler

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/user")]
        (is (= status 401))
        (is (= body {:error "Unauthorized"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/dev/login")]
        (is (= status 200))
        (is (= body {:id 123 :name "Name" :picture "http://127.0.0.1:8084/avatar?user=dev-user"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/user")]
        (is (= status 200))
        (is (= body {:id 123 :name "Name" :picture "http://127.0.0.1:8084/avatar?user=dev-user"}))))))

(deftest ^:integration logout-test
  (with-http-client
    (with-server
      handler

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/dev/login")]
        (is (= status 200))
        (is (= body {:id 123 :name "Name" :picture "http://127.0.0.1:8084/avatar?user=dev-user"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/logout")]
        (is (= status 200))
        (is (= body nil)))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/private")]
        (is (= status 401))
        (is (= body {:error "Unauthorized"}))))))

(deftest ^:integration bad-request-test
  (with-http-client
    (with-server
      handler

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/prov/login")]
        (is (= status 400))
        (is (= body {:error "provider not supported"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/")]
        (is (= status 400))
        (is (= body {:error "provider not supported"})))

      (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/test/test")]
        (is (= status 400))
        (is (= body {:error "provider not supported"}))))))

(deftest ^:integration logout-no-providers-test
  (let [handler (ring/ring-handler (ring/router [["/auth/*" (auth/handlers {})]] route-middleware))]
    (with-http-client
      (with-server
        handler

        (let [{:keys [status body]} (client-get "http://127.0.0.1:8981/auth/logout")]
          (is (= status 400))
          (is (= body {:error "providers not defined"})))))))

