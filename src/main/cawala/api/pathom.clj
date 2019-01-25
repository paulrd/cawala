(ns cawala.api.pathom
  (:require [com.wsscode.pathom.connect :as pc]
            [com.wsscode.pathom.core :as p]
            [cawala.api.mutations :as m]
            [cawala.api.read :as r]
            [cawala.api.db :as db]))

(def app-registry [r/current-user r/my-friends r/my-enemies r/person-resolver
                   m/delete-person])

(def parser
  (p/parallel-parser
   {::p/env     {::p/reader [p/map-reader pc/parallel-reader pc/open-ident-reader
                             p/env-placeholder-reader]
                 ::p/process-error
                 (fn [_ err] (.printStackTrace err) (p/error-str err))
                 ::db/db db/people-db
                 ::pc/mutation-join-globals [:app/id-remaps]
                 ::p/placeholder-prefixes #{">"}}
    ::p/mutate  pc/mutate-async
    ;; setup connect and use our resolvers
    ::p/plugins [(pc/connect-plugin {::pc/register app-registry})
                 p/error-handler-plugin
                 p/request-cache-plugin
                 p/trace-plugin]}))

(comment
  p/env-wrap-plugin

  )
