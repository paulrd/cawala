(ns ca.cawala.swing
  (:use [seesaw.core])
  (:import [org.pushingpixels.radiance.theming.api RadianceThemingCortex RadianceThemingCortex$GlobalScope]))

(defn laf-selector []
  (horizontal-panel
   :items ["Radiance skin: "
           (combobox
            :model    (vals (RadianceThemingCortex$GlobalScope/getAllSkins))
            :renderer (fn [this {:keys [value]}]
                        (text! this (.getClassName value)))
            :listen   [:selection (fn [e]
                                        ; Invoke later because CB doens't like changing L&F while
                                        ; it's doing stuff.
                                    (invoke-later
                                     (-> e
                                         selection
                                         .getClassName
                                         RadianceThemingCortex$GlobalScope/setSkin)))])]))

(def notes " This example shows the available Radiance skins. Radiance
is a set of improved look and feels for Swing. To use it in a project,
you'll need to add a dep to your Leiningen project:

        [org.pushing-pixels/radiance-theming \"7.5.0\"]

In this example, the full class name of the current skin is shown the
in the combobox above. For your own apps you could either use a
selector like this example, or, more likely, set a default initial
skin in one of the following ways:

    Start your VM with -Dswing.defaultlaf=<class-name>

    Call (javax.swing.UIManager/setLookAndFeel \"<class-name>\")
    do this *after* (seesaw.core/native!) since that sets the L&F.

See https://github.com/kirill-grouchnikov/radiance/blob/sunshine/docs/theming/getting-started.md
for more info. There you'll also find much more info about the
skins along with much less crappy looking demos.")

(defn launch []
  (invoke-later
   (->
    (frame
     :title "Seesaw Radiance Example"
     :on-close :dispose
     :content (vertical-panel
               :items [(laf-selector)
                       (text :multi-line? true :text notes :border 5)
                       :separator
                       (label :text "A Label")
                       (button :text "A Button")
                       (checkbox :text "A checkbox")
                       (combobox :model ["A combobox" "more" "items"])
                       (horizontal-panel
                        :border "Some radio buttons"
                        :items (map (partial radio :text)
                                    ["First" "Second" "Third"]))
                       (scrollable (listbox :model (range 100)))]))
    pack!
    show!)))

(defn -main [& args]
  (launch)
  )

(comment
  (launch)
  (println "hi")
  (= 1 2)
  )
