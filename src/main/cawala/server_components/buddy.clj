(ns cawala.server-components.buddy
  (:require [ring.util.response :refer [response redirect content-type]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication]]))

;; Simple ring handler. This can also be a compojure router handler
;; or anything else compatible with ring middleware.

(defn my-handler
  [request]
  (if (:identity request)
    (response (format "Hello %s" (:identity request)))
    (response "Hello Anonymous")))

(defn my-authfn
  [request authdata]
  (let [username (:username authdata)
        password (:password authdata)]
    username))

(def backend (backends/basic {:realm "MyApi"
                              :authfn my-authfn}))

;; Define the main handler with *app* name wrapping it with authentication
;; middleware using an instance of the just created http-basic backend.

;; Define app var with handler wrapped with _buddy-auth_'s authentication
;; middleware using the previously defined backend.

(def app (wrap-authentication my-handler backend))

(comment
(as->)

  )
