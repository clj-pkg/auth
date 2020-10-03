(ns example.reitit-auth
  (:require [reitit.ring :as ring]
            [clj-pkg.auth :as auth]
            [ring.middleware.json :as json-mw]
            [ring.middleware.cookies :as cookies]
            [reitit.ring.middleware.parameters :as parameters]
            [ring.adapter.jetty :as jetty]
            [clojure.string :refer [starts-with?]])
  (:gen-class))

(def cookies-middleware
  {:name ::cookies
   :wrap cookies/wrap-cookies})

(def json-response-middleware
  {:name ::json-response
   :wrap json-mw/wrap-json-response})

(def route-middleware {:data {:middleware [parameters/parameters-middleware
                                           json-response-middleware
                                           cookies-middleware]}})

(def auth-params {:secret          "jwt secret"
                  :token-duration  60
                  :cookie-duration (* 60 60 24)
                  :issuer          "my-service"
                  :claims-upd      (fn [claims]             ; sets additional user parameters during login
                                     (if (= (-> claims :user :name) "dev_admin")
                                       (assoc-in claims [:user :is-admin] true)
                                       claims))
                  :validator       (fn [_ claims]           ; allow users only with google and dev providers
                                     (or
                                       (starts-with? (-> claims :user :id) "google_")
                                       (starts-with? (-> claims :user :id) "dev_")))
                  :providers       {:google {:client-id     "<google-client-id>"
                                             :client-secret "<google-client-secret>"}
                                    :github {:client-id     "<github-client-id>"
                                             :client-secret "<github-client-secret>"}
                                    :dev    {:automatic? false}}})

(def handler (ring/ring-handler
               (ring/router [["/auth/*" (auth/handlers auth-params)]
                             ["/open" {:handler (fn [_] {:status 200 :body {:data "open data"}})}]
                             ["/private" {:middleware [(auth/middleware auth-params)]
                                          :handler    (fn [_] {:status 200 :body {:data "private data"}})}]]
                            route-middleware)
               (ring/routes
                 (ring/create-resource-handler {:path "/"})
                 (ring/create-default-handler {:not-found (constantly {:status 404 :body "Not found"})}))))

(defn -main [& _]
  (auth/run-dev-oauth2 auth-params)
  (jetty/run-jetty handler {:port 8080 :join? true}))
