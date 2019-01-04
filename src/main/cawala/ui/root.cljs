(ns cawala.ui.root
  (:require
    [fulcro.client.dom :as dom :refer [div]]
    [fulcro.client.data-fetch :as df]
    ["semantic-ui-react" :refer [Dropdown DropdownItem DropdownMenu]]
    [fulcro.client.primitives :as prim :refer [defsc]]
    [cawala.ui.components :as comp]))

(defn ui-dropdown [& args] (dom/macro-create-element Dropdown args))
(defn ui-dropdown-menu [& args] (dom/macro-create-element DropdownMenu args))
(defn ui-dropdown-item [& args] (dom/macro-create-element DropdownItem args))

(defsc SomeComponent [this props]
  (ui-dropdown {:text "Filter"}
               (ui-dropdown-menu {}
                                 (ui-dropdown-item {} "A")
                                 (ui-dropdown-item {} "B"))))

(def ui-some-component (prim/factory SomeComponent))

;; Root's initial state becomes the entire app's initial state!
(defsc Root [this {:keys [ui/react-key friends enemies current-user]}]
  {:query [:ui/react-key
           {:current-user (prim/get-query comp/Person)}
           {:friends (prim/get-query comp/PersonList)}
           {:enemies (prim/get-query comp/PersonList)}]
   :initial-state
   (fn [params] {:friends (prim/get-initial-state
                          comp/PersonList {:id :friends :label "Friends"})
                :enemies (prim/get-initial-state
                          comp/PersonList {:id :enemies :label "Enemies"})})}
  (dom/div
   (dom/h4 (str "Current User: " (:person/name current-user)))
   (dom/button {:onClick (fn [] (df/load this [:person/by-id 3] comp/Person))}
               "Refresh Person with ID 3")
   (comp/ui-person-list friends)
   (comp/ui-person-list enemies)
   (ui-some-component)))

(comment
  (prim/get-initial-state Root {})
  @(prim/app-state (get @cawala.client/app :reconciler))
  (prim/db->tree [{:friends [:person-list/label]}]
                 (prim/get-initial-state Root {} {})
                 {:friends {:person-list/label "Friends"}})
  (let [current-db @(prim/app-state
                     (-> cawala.client/app deref :reconciler))
        root-query (prim/get-query Root)]
    (prim/db->tree root-query current-db current-db))
  (cljs.repl/dir fulcro.client.dom)
  (js/alert "hi")
  )
