(ns cawala.client
  (:require [fulcro.client :as fc]
            [fulcro.client.data-fetch :as df]
            [cawala.ui.components :as comp]
            [cawala.ui.root :as root]
            [cawala.api.mutations :as api]
            [fulcro.client.network :as net]))

(defonce app (atom nil))

(defn mount []
  (reset! app (fc/mount @app root/Root "app")))

(defn start []
  (mount))

(def secured-request-middleware
  ;; The CSRF token is embedded in the server_components/html.clj
  (->
    (net/wrap-csrf-token (or js/fulcro_network_csrf_token "TOKEN-NOT-IN-HTML!"))
    (net/wrap-fulcro-request)))

(defn ^:export init []
  (reset! app
          (fc/new-fulcro-client
           ;; This ensures your client can talk to a CSRF-protected server.
           ;; See middleware.clj to see how the token is embedded into the HTML
           :started-callback
           (fn [app]
             (df/load app :current-user comp/Person)
             (df/load app :my-enemies comp/Person
                      {:target [:person-list/by-id :enemies :person-list/people]
                       :post-mutation `api/sort-friends})
             (df/load app :my-friends comp/Person
                      {:target [:person-list/by-id :friends :person-list/people]}))
           :networking
           {:remote (net/fulcro-http-remote
                     {:url (str (-> js/window .-location .-href) "api")
                          :request-middleware secured-request-middleware})}))
  (start))

(comment
  (js/alert "hi")
  (-> js/window .-location .-href type)
  (println "hi")
  (doc 'cawala.client)
  (cljs.repl/dir cljs.repl)
  )
