(ns clj-pkg.railway)

(defn apply-or-error [f [val err]]
  (if (nil? err)
    (f val)
    [nil err]))

(defmacro => [val & fns]
  (let [fns (for [f fns] `(apply-or-error ~f))]
    `(->> [~val nil]
          ~@fns)))

(defn success [msg] [msg nil])
(defn fail [err] [nil err])
