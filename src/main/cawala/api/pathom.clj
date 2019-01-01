(ns cawala.api.pathom
  (:require [com.wsscode.pathom.core :as p]
            [com.wsscode.pathom.connect :as pc]
            [com.wsscode.pathom.profile :as pp]
            [clojure.core.async :as a]))

(def product->brand {1 "Taylor"})
(def brand->id {"Taylor" 44151})

;; Define one or more resolvers
#_(pc/defresolver person-resolver [{:keys [database] :as env} {:keys [person/id]}]
  {::pc/input #{:person/id}
   ::pc/output [:person/first-name :person/age]}
  (let [person (my-database/get-person database id)]
    {:person/age        (:age person)
     :person/first-name (:first-name person)}))

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
                    :user/created-at (js/Date.)}))]
    (swap! db assoc-in [:users id] new-user)
    {:user/id id}))

;; resolvers are just maps, we can compose many using sequences
(def app-registry [latest-product product-brand brand-id-from-name list-things
                   slow-resolver send-message])

;; Create a parser that uses the resolvers:
#_(def parser
  (p/parallel-parser
    {::p/env     {::p/reader               [p/map-reader
                                            pc/parallel-reader
                                            pc/open-ident-reader
                                            p/env-placeholder-reader]
                  ::p/placeholder-prefixes #{">"}}
     ::p/mutate  pc/mutate-async
     ;; setup connect and use our resolvers
     ::p/plugins [(pc/connect-plugin {::pc/register app-registry})
                  p/error-handler-plugin
                  p/request-cache-plugin
                  p/trace-plugin]}))

(def parser
  (p/parallel-parser
   {::p/env     {::p/reader [p/map-reader
                             pc/parallel-reader
                             pc/open-ident-reader]}
    ::p/mutate  pc/mutate-async
    ::p/plugins [(pc/connect-plugin {::pc/register app-registry})
                 p/error-handler-plugin
                 p/request-cache-plugin
                 p/trace-plugin]}))

#_(def parser
  (p/async-parser
   {::p/env     {::p/reader [p/map-reader
                             pc/async-reader2
                             pc/open-ident-reader]
                 ::p/process-error (fn [env error]
                                     (p/error-str error))}
    ::p/mutate  pc/mutate-async
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
  (a/<!! (parser {} q))
  (def q '[(send-message {:message/text "Hello Clojurist!"})])
  (a/<!! (parser {} q))
  (java.time.Instant.)
)
