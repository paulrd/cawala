(ns cawala.api.read
  (:require [com.wsscode.pathom.connect :as pc]
            [com.wsscode.pathom.core :as p]
            [taoensso.timbre :as timbre]
            [clojure.core.async :as a]))

(def people-db (atom
                {1  {:db/id 1 :person/name "Bert" :person/age 55
                     :person/relation :friend}
                 2  {:db/id 2 :person/name "Sally" :person/age 22
                     :person/relation :friend}
                 3  {:db/id 3 :person/name "Allie" :person/age 56
                     :person/relation :enemy}
                 4  {:db/id 4 :person/name "Zoe" :person/age 32
                     :person/relation :friend}
                 99 {:db/id 99 :person/name "Me" :person/role "admin"}}))

(defn get-people [kind]
  (->> @people-db
       vals
       (filter #(= kind (:person/relation %)))
       vec))

(pc/defresolver current-user [{::keys [db]} _]
  {::pc/output [{:current-user [:db/id :perosn/age :person/name]}]}
  {:current-user (get @db 99)})

(pc/defresolver my-friends [{::keys [db]} _]
  {::pc/output [{:my-friends [:db/id :perosn/age :person/name]}]}
  {:my-friends (get-people :friend)})

(pc/defresolver my-enemies [{::keys [db]} _]
  {::pc/output [{:my-enemies [:db/id :perosn/age :person/name]}]}
  {:my-enemies (get-people :enemy)})

(pc/defresolver person-resolver [{::keys [db]} {:keys [person/by-id]}]
  {::pc/input #{:person/by-id}
   ::pc/output [:db/id :person/name :person/age]}
  (update (get @db by-id) :person/name str " (refreshed)"))

(pc/defmutation delete-person [{::keys [db]} {:keys [person-id]}]
  {::pc/params [:person-id]
   ::pc/sym 'cawala.api.mutations/delete-person}
    (do
      (timbre/info "Server deleting person" person-id)
      (swap! db dissoc person-id)
      nil))

(def app-registry [current-user my-friends my-enemies person-resolver
                   delete-person])

(def parser
  (p/parallel-parser
   {::p/env     {::p/reader [p/map-reader pc/parallel-reader pc/open-ident-reader
                             p/env-placeholder-reader]
                 ::pc/mutation-join-globals [:app/id-remaps]
                 ::db people-db
                 ::p/placeholder-prefixes #{">"}}
    ::p/mutate  pc/mutate-async
    ;; setup connect and use our resolvers
    ::p/plugins [(pc/connect-plugin {::pc/register app-registry})
                 p/error-handler-plugin
                 p/request-cache-plugin
                 p/trace-plugin]}))

(comment
  (def q [{[:person/by-id 2] [:db/id :person/name :person/age]}])
  (def q `[(delete-jaba {:list-id 1 :person-id 1})])
  (def q `[(delete-person {:list-id 1 :person-id 1})])
  (a/<!! (parser {} q))
  @people-db
  )
