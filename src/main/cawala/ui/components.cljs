(ns cawala.ui.components
  (:require [fulcro.client.primitives :as prim :refer [defsc]]
            [fulcro.client.data-fetch :as df]
            [fulcro.client.dom :as dom]
            [cawala.api.mutations :as api]))

(defsc Person [this {:keys [db/id person/name person/age]} {:keys [onDelete]}]
  {:query         [:db/id :person/name :person/age]
   :ident [:person/by-id :db/id]
   :initial-state (fn [{:keys [id name age]}]
                    {:db/id id :person/name name :person/age age})}
  (dom/li
   (dom/h5 (str name "(age: " age ")")
           (dom/button {:onClick #(onDelete id)} "A")
           (dom/button {:onClick #(df/refresh! this)} "Refresh"))))

(def ui-person (prim/factory Person {:keyfn :person/name}))

(defsc PersonList [this {:keys [db/id person-list/label person-list/people]}]
  {:query [:db/id :person-list/label
           {:person-list/people (prim/get-query Person)}]
   :ident [:person-list/by-id :db/id]
   :initial-state
   (fn [{:keys [id label]}]
     {:db/id id
      :person-list/label  label
      :person-list/people []})}
  (let [delete-person
        (fn [person-id]
          (prim/transact!
           this
           `[(api/delete-person {:list-id ~id :person-id ~person-id})]))]
    (dom/div
     (dom/h4 label)
     (dom/ul
      (map (fn [p] (ui-person (prim/computed p {:onDelete delete-person})))
           people)))))

(def ui-person-list (prim/factory PersonList))

(comment
  (println "yes?")
  (meta (prim/get-query PersonList))
  )
