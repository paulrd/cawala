(ns cawala.api.pathom
  (:require [com.wsscode.pathom.core :as p]
            [com.wsscode.pathom.connect :as pc]
            [com.wsscode.pathom.profile :as pp]
            [clojure.core.async :as a]))

(def product->brand {1 "Taylor"})
(def brand->id {"Taylor" 44151})

(pc/defresolver latest-product [_ _]
  {::pc/output [{::latest-product [:product/id :product/title :product/price]}]}
  {::latest-product {:product/id    1
                     :product/title "Acoustic Guitar"
                     :product/price 199.99M}})

(pc/defresolver product-brand [_ {:keys [product/id]}]
  {::pc/input  #{:product/id}
   ::pc/output [:product/brand]}
  {:product/brand (get product->brand id)})

(pc/defresolver brand-id-from-name [_ {:keys [product/brand]}]
  {::pc/input #{:product/brand}
   ::pc/output [:product/brand-id]}
  {:product/brand-id (get brand->id brand)})

(pc/defresolver list-things [_ _]
  {::pc/output [{:items [:number]}]}
  {:items [{:number 3}
           {:number 10}
           {:number 18}]})

(pc/defresolver slow-resolver [_ input]
  {::pc/input  #{:number}
   ::pc/output [:number-added]
   ::pc/batch? true}
  (a/go
    (a/<! (a/timeout 1000))
    (if (sequential? input)
      (mapv (fn [v] {:number-added (inc (:number v))}) input)
      {:number-added (inc (:number input))})))

(pc/defmutation send-message [env {:keys [message/text]}]
  {::pc/sym    'send-message
   ::pc/params [:message/text]
   ::pc/output [:message/id :message/text]}
  {:message/id   123
   :message/text text})

(pc/defmutation create-user [{::keys [db]} user]
  {::pc/sym    'user/create
   ::pc/params [:user/name :user/email]
   ::pc/output [:user/id]}
  (let [{:keys [user/id] :as new-user}
        (-> user
            (select-keys [:user/name :user/email])
            (merge {:user/id (java.util.UUID/randomUUID)
                    :user/created-at (.toString (java.time.Instant/now))}))]
    (swap! db assoc-in [:users id] new-user)
    {:user/id id}))

(pc/defresolver user-data [{::keys [db]} {:keys [user/id]}]
  {::pc/input  #{:user/id}
   ::pc/output [:user/id :user/name :user/email :user/created-at]}
  (get-in @db [:users id]))

(pc/defresolver all-users [{::keys [db]} _]
  {::pc/output [{:user/all [:user/id :user/name :user/email :user/created-at]}]}
  (vals (get db :users)))

(pc/defmutation user-create [{::keys [db]} user]
  {::pc/sym    'user/createAs
   ::pc/params [:user/name :user/email]
   ::pc/output [:user/id]}
  (let [{:keys [user/id] :as new-user}
        (-> user
            (select-keys [:user/name :user/email])
            (merge {:user/id (java.util.UUID/randomUUID)
                    :user/created-at (.toString (java.time.Instant/now))}))]
    (swap! db assoc-in [:users id] new-user)
    {:user/id       id
     :app/id-remaps {(:user/id user) id}}))

;; resolvers are just maps, we can compose many using sequences
(def app-registry [latest-product product-brand brand-id-from-name list-things
                   slow-resolver send-message create-user user-data all-users
                   user-create])

;; Create a parser that uses the resolvers:
(def parser
  (p/parallel-parser
    {::p/env     {::p/reader [p/map-reader pc/parallel-reader pc/open-ident-reader
                              p/env-placeholder-reader]
                  ::pc/mutation-join-globals [:app/id-remaps]
                  ::p/placeholder-prefixes #{">"}
                  }
     ::p/mutate  pc/mutate-async
     ;; setup connect and use our resolvers
     ::p/plugins [(pc/connect-plugin {::pc/register app-registry})
                  p/error-handler-plugin
                  p/request-cache-plugin
                  p/trace-plugin]}))

;; note the parallel parser call will return a channel, you must read the value
;; on it to get the parser results

(comment
  (def q [{::latest-product [:product/title :product/brand]}])
  (def q [{::latest-product [:product/title :product/brand-id]}])
  (def q [{[:product/id 1] [:product/brand]}])
  (def q [{[:product/brand "Taylor"] [:product/brand-id]}])
  (def q [{([:customer/id 123] {:pathom/context {:customer/first-name "Foo"
                                                 :customer/last-name "Bar"}})
           [:customer/full-name]}])
  (def q [{:items [:number-added]}])
  (def q '[(send-message {:message/text "Hello Clojurist!"})])
  (def q '[{(user/create {:user/name "Rick Sanches" :user/email "rick@morty.com"})
            [:user/id :user/name :user/created-at]}])
  (def q '[{(user/create {:user/id "TMP_ID" :user/name "Rick Sanches"
                          :user/email "rick@morty.com"})
            [:user/id :user/name :user/created-at]}])
  (a/<!! (parser {} q))
)
