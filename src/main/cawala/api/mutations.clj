(ns cawala.api.mutations
  (:require [taoensso.timbre :as timbre]
            ;; this dependency is just for namespaced keys I'm getting the db
            ;; from the parser environment.
            [cawala.api.db :as db]
            [com.wsscode.pathom.connect :as pc]))

;; Place your server mutations here
(pc/defmutation delete-person [{::db/keys [db]} {:keys [person-id]}]
    {::pc/params [:person-id]
     ::pc/sym 'cawala.api.mutations/delete-person}
  (timbre/info "Server deleting person" person-id)
  (swap! db dissoc person-id)
  nil)
