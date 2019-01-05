(ns cawala.api.read
  (:require [com.wsscode.pathom.connect :as pc]
            #_[com.wsscode.pathom.core :as p]
            [taoensso.timbre :as timbre]
            ;; this dependency is just for namespaced keys I'm getting the db
            ;; from the parser environment.
            [cawala.api.db :as db]
            [clojure.core.async :as a]))

(defn get-people [db kind]
  (->> @db
       vals
       (filter #(= kind (:person/relation %)))
       vec))

(pc/defresolver current-user [{::db/keys [db]} _]
  {::pc/output [{:current-user [:db/id :perosn/age :person/name]}]}
  {:current-user (get @db 99)})

(pc/defresolver my-friends [{::db/keys [db]} _]
  {::pc/output [{:my-friends [:db/id :perosn/age :person/name]}]}
  {:my-friends (get-people db :friend)})

(pc/defresolver my-enemies [{::db/keys [db]} _]
  {::pc/output [{:my-enemies [:db/id :perosn/age :person/name]}]}
  {:my-enemies (get-people db :enemy)})

(pc/defresolver person-resolver [{::db/keys [db]} {:keys [person/by-id]}]
  {::pc/input #{:person/by-id}
   ::pc/output [:db/id :person/name :person/age]}
  (update (get @db by-id) :person/name str " (refreshed)"))
