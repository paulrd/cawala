(ns cawala.workspaces
  (:require
    [nubank.workspaces.core :as ws]
    [cawala.demo-ws]))

(defonce init (ws/mount))
