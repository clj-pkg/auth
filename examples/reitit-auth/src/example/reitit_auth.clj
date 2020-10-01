(ns example.reitit-auth
  (:require [reitit.ring :as ring]
            [clj-pkg.auth :as auth]
            [ring.middleware.json :as json-mw]
            [ring.middleware.cookies :as cookies]
            [reitit.ring.middleware.parameters :as parameters]
            [ring.adapter.jetty :as jetty])
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
                  :claims-upd      (fn [] (prn "TODO"))
                  :validator       (fn [] (prn "TODO"))
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
