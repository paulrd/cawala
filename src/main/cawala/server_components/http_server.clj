(ns cawala.server-components.http-server
  (:require
    [cawala.server-components.config :refer [config]]
    [cawala.server-components.middleware :refer [middleware]]
    [mount.core :refer [defstate]]
    [org.httpkit.server :as http-kit]))

(defstate http-server
  :start (http-kit/run-server middleware (:http-kit config))
  :stop (http-server))
