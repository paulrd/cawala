(ns cawala.auth
  (:require [taoensso.timbre :as log]
            [cawala.util :as util]
            [cawala.api.db :as db])
  (:import (java.security SecureRandom)
           (javax.crypto SecretKeyFactory)
           (javax.crypto.spec PBEKeySpec)
           (java.util Base64$Encoder Base64)))

(defn ^String gen-salt []
  (let [sr (SecureRandom/getInstance "SHA1PRNG")
        salt (byte-array 16)]
    (.nextBytes sr salt)
    (String. salt)))

(defn ^String encrypt
  "Encrypt the given password, returning a string."
  [^String password ^String salt ^Long iterations]
  (let [keyLength           512
        password-characters (.toCharArray password)
        salt-bytes          (.getBytes salt "UTF-8")
        skf                 (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA512")
        spec                (new PBEKeySpec password-characters salt-bytes iterations keyLength)
        key                 (.generateSecret skf spec)
        res                 (.getEncoded key)
        hashed-pw           (.encodeToString (Base64/getEncoder) res)]
    hashed-pw))

 (defn validate-user
    "Validate a user. Returns boolean true if they are valid."
    [db incoming-email incoming-password]
    (let [{:user/keys [email encrypted-password password-salt password-iterations]}




          #_(d/pull db [:user/email
                        :user/encrypted-password
                        :user/password-salt
                        :user/password-iterations]
                    [:user/email incoming-email])

          hashed (when (and email encrypted-password password-salt password-iterations)
                   (encrypt incoming-password password-salt password-iterations))]
      (cond
        (not= incoming-email email)
        (do
          (log/error "Attempted validation for invalid username" incoming-email)
          false)

        (= hashed encrypted-password)
        (do
          (log/info "Valid credentials for" incoming-email)
          true)

        :else (do
                (log/error "Invalid credentials for username" incoming-email)
                false))))
