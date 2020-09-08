(ns example.reitit-auth
  (:gen-class))

(def auth-params {:secret          "jwt secret"
                  :token-duration  60
                  :cookie-duration (* 60 60 24)             ; keep cookie for 24 hours
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
                             ["/private" {:middleware [auth/middleware]
                                          :handler    (fn [_] {:status 200 :body {:data "private data"}})}]]
                            route-middleware)))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))
