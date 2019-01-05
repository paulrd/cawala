(ns cawala.api.mutations
  (:require [taoensso.timbre :as timbre]
            [cawala.api.db :as db]
            [com.wsscode.pathom.connect :as pc]))

;; Place your server mutations here
(pc/defmutation delete-person [_ {:keys [person-id]}]
    {::pc/params [:person-id]
     ::pc/sym 'cawala.api.mutations/delete-person}
  (timbre/info "Server deleting person" person-id)
  (swap! db/people-db dissoc person-id)
  nil)

(comment
  (def db {:a 1 :b 2})
  (def db {::a 1 ::b 2})
  (def db {:person/a 1 :person/b 2})
  (let [{::keys [a b]} db]
    [a b])
  (let [{:keys [cawala.api.mutations/a cawala.api.mutations/b]} db]
    [a b])
  (let [{:person/keys [a b]} db]
    [a b])
  )
