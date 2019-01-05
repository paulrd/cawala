(ns cawala.api.read
  (:require [com.wsscode.pathom.connect :as pc]
            #_[com.wsscode.pathom.core :as p]
            [taoensso.timbre :as timbre]
            [clojure.core.async :as a]))

(defn get-people [db kind]
  (->> @db
       vals
       (filter #(= kind (:person/relation %)))
       vec))

(pc/defresolver current-user [{::keys [db]} _]
  {::pc/output [{:current-user [:db/id :perosn/age :person/name]}]}
  {:current-user (get @db 99)})

(pc/defresolver my-friends [{::keys [db]} _]
  {::pc/output [{:my-friends [:db/id :perosn/age :person/name]}]}
  {:my-friends (get-people db :friend)})

(pc/defresolver my-enemies [{::keys [db]} _]
  {::pc/output [{:my-enemies [:db/id :perosn/age :person/name]}]}
  {:my-enemies (get-people db :enemy)})

(pc/defresolver person-resolver [{::keys [db]} {:keys [person/by-id]}]
  {::pc/input #{:person/by-id}
   ::pc/output [:db/id :person/name :person/age]}
  (update (get @db by-id) :person/name str " (refreshed)"))

#_(pc/defmutation delete-person [{::keys [db]} {:keys [person-id]}]
  {::pc/params [:person-id]
   ::pc/sym 'cawala.api.mutations/delete-person}
  (timbre/info "Server deleting person" person-id)
  (swap! db dissoc person-id)
  )
