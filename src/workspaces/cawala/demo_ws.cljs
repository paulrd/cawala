(ns cawala.demo-ws
  (:require [fulcro.client.primitives :as fp]
            [fulcro.client.data-fetch :as df]
            [cawala.ui.components :as comp]
            [cawala.api.mutations :as api]
            [fulcro.client.network :as net]
            [fulcro.client.localized-dom :as dom]
            [nubank.workspaces.core :as ws]
            [nubank.workspaces.card-types.fulcro :as ct.fulcro]
            [nubank.workspaces.lib.fulcro-portal :as f.portal]
            [cawala.ui.root :as root]
            [fulcro.client.mutations :as fm]))

(fp/defsc FulcroDemo
  [this {:keys [counter]}]
  {:initial-state (fn [_] {:counter 0})
   :ident         (fn [] [::id "singleton"])
   :query         [:counter]}
  (dom/div
    (str "Fulcro counter demo [" counter "]")
    (dom/button {:onClick #(fm/set-value! this :counter (inc counter))} "+")))

(ws/defcard fulcro-demo-card
  (ct.fulcro/fulcro-card
    {::f.portal/root FulcroDemo}))

(def request-middleware
  (-> (net/wrap-csrf-token (or js/fulcro_network_csrf_token "TOKEN-NOT-IN-HTML!"))
      net/wrap-fulcro-request))

(ws/defcard cawala-card
  (ct.fulcro/fulcro-card
   {::f.portal/root root/Root
    ::f.portal/app {:started-callback
                    (fn [app]
                      (df/load app :current-user comp/Person)
                      (df/load app :my-enemies comp/Person
                               {:target [:person-list/by-id :enemies :person-list/people]
                                :post-mutation `api/sort-friends})
                      (df/load app :my-friends comp/Person
                               {:target [:person-list/by-id :friends :person-list/people]}))
                    ;; This ensures your client can talk to a CSRF-protected server.
                    ;; See middleware.clj to see how the token is embedded into the HTML
                    :networking
                    {:remote (net/fulcro-http-remote
                              {:url (str #_(-> js/window .-location .-href) "/api")
                               :request-middleware request-middleware
                               :response-middleware (net/wrap-fulcro-response)})}}}))
