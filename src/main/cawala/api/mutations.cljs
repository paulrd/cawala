(ns cawala.api.mutations
  (:require [fulcro.client.mutations :as m :refer [defmutation]]))

(defmutation delete-person
  "Mutation: Delete the person with name from the list with list-name"
  [{:keys [list-id person-id]}]
  (action [{:keys [state]}]
          (let [ident-to-remove [:person/by-id person-id]
                strip-fk (fn [old-fks]
                           (vec (filter #(not= ident-to-remove %) old-fks)))]
            (swap! state update-in
                   [:person-list/by-id list-id :person-list/people]
                   strip-fk)))
  (remote [env] true))

(defn sort-friends-by*
  "Sort the idents in the friends person list by the indicated field. Returns the
  new app-state."
  [state-map field]
  (let [friend-idents (get-in state-map
                              [:person-list/by-id :friends :person-list/people] [])
        friends (map (fn [friend-ident]
                       (get-in state-map friend-ident)) friend-idents)
        sorted-friends (sort-by field friends)
        new-idents (mapv (fn [friend]
                           [:person/by-id (:db/id friend)]) sorted-friends)]
    (assoc-in state-map [:person-list/by-id :friends :person-list/people]
              new-idents)))

(defmutation sort-friends [no-params]
  (action [{:keys [state]}]
          (swap! state sort-friends-by* :person/name)))
