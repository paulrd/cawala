(ns cawala.api.db)

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
