(ns cawala.api.pathom
  (:require [com.wsscode.pathom.connect :as pc]
            [com.wsscode.pathom.core :as p]
            [cawala.api.mutations :as m]
            [clojure.core.async :as a]
            [cawala.api.read :as r]))

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

(def app-registry [r/current-user r/my-friends r/my-enemies r/person-resolver
                   m/delete-person])

(def parser
  (p/parallel-parser
   {::p/env     {::p/reader [p/map-reader pc/parallel-reader pc/open-ident-reader
                             p/env-placeholder-reader]
                 ::p/proces-error
                 (fn [_ err]
                   ;; print stack trace
                   (.printStackTrace err)
                   ;; return error str
                   (p/error-str err))
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
  (def q `[(m/delete-person {:list-id 1 :person-id 1})])
  (a/<!! (parser {} q))
  @people-db
  )
