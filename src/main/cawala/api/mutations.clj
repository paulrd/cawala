(ns cawala.api.mutations
  (:require
   [taoensso.timbre :as timbre]
   #_[com.wsscode.pathom.core :as p]
   [com.wsscode.pathom.connect :as pc]
   #_[cawala.api.read :as r]
   #_[fulcro.server :refer [defmutation]]))

;; Place your server mutations here
#_(defmutation delete-person
  "Server Mutation: Handles deleting a person on the server"
  [{:keys [person-id]}]
  (action [{:keys [state]}]
          (timbre/info "Server deleting person" person-id)
          (swap! people-db dissoc person-id)))

#_(def delete-person r/delete-person)

(pc/defmutation delete-person [{::keys [db]} {:keys [person-id]}]
    {::pc/params [:person-id]
     ::pc/sym 'cawala.api.mutations/delete-person}
    (do
      (timbre/info "Server deleting person" person-id)
      (swap! db dissoc person-id)
      nil))
