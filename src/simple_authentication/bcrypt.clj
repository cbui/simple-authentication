(ns simple-authentication.bcrypt
  (:import org.mindrot.jbcrypt.BCrypt))

(defn hash-password
  ([password]
     "Hashes the password with BCrypt and a generated salt. The generated salt defaults to 10 log_rounds (How complex the salt is)."
     (BCrypt/hashpw password (BCrypt/gensalt)))
  ([password salt]
     "Hashes the password with BCrypt and the given salt."
     (BCrypt/hashpw password salt)))

(defn plain-text-matches-hashed?
  [plain-text-password hashed-password]
  "Checks the plain-text-password against the hashed-password. Returns true if they match and false if they don't."
  (BCrypt/checkpw plain-text-password hashed-password))