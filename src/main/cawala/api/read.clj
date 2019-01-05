(ns cawala.api.read
  (:require [com.wsscode.pathom.connect :as pc]
            #_[com.wsscode.pathom.core :as p]
            [taoensso.timbre :as timbre]
            [cawala.api.db :as db]
            [clojure.core.async :as a]))

(defn get-people [kind]
  (->> @db/people-db
       vals
       (filter #(= kind (:person/relation %)))
       vec))

(pc/defresolver current-user [_ _]
  {::pc/output [{:current-user [:db/id :perosn/age :person/name]}]}
  {:current-user (get @db/people-db 99)})

(pc/defresolver my-friends [_ _]
  {::pc/output [{:my-friends [:db/id :perosn/age :person/name]}]}
  {:my-friends (get-people :friend)})

(pc/defresolver my-enemies [_ _]
  {::pc/output [{:my-enemies [:db/id :perosn/age :person/name]}]}
  {:my-enemies (get-people :enemy)})

(pc/defresolver person-resolver [_ {:keys [person/by-id]}]
  {::pc/input #{:person/by-id}
   ::pc/output [:db/id :person/name :person/age]}
  (update (get @db/people-db by-id) :person/name str " (refreshed)"))
