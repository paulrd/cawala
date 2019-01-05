(ns cawala.server-components.hbank
  (:require [hiccup.page :as p])
  )

(defn head [csrf-token]
  [:head
   [:meta {:charset "utf-8"}]
   [:title "W3.CSS Template"]
   [:meta {:name "viewport"
           :content "width=device-width, initial-scale=1"}]
   (p/include-css
    "https://www.w3schools.com/w3css/4/w3.css"
    "https://fonts.googleapis.com/css?family=Raleway"
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css")
   [:link {:rel "shortcut icon" :href "data:image/x-icon;," :type "image/x-icon"}]
   [:script (str "var fulcro_network_csrf_token = '" csrf-token "';")]
   [:style "html,body,h1,h2,h3,h4,h5 {font-family: Raleway, sans-serif}"]])

(def top-container
  [:div.w3-bar.w3-top.w3-black.w3-large {:style "z-index:4"}
   [:button.w3-bar-item.w3-button.w3-hide-large.w3-hover-none.w3-hover-text-light-grey
    {:onClick "w3_open();"}
    [:i.fa.fa-bars] "Menu"]
   [:span.w3-bar-item.w3-right "Logo"]])

(def sidebar-menu
  [:nav#mySidebar.w3-sidebar.w3-collapse.w3-white.w3-animate-left
   {:style "z-index:3;width:300px;"} [:br]
   [:div.w3-container.w3-row
    [:div.w3-col.s4 [:img.w3-circle.w3-margin-right {:src "/w3images/avatar2.png"
                                                     :style "width:46px"}]]
    [:div.w3-col.s8.w3-bar
     [:span "Welcome, " [:strong "Mike"]] [:br]
     [:a.w3-bar-item.w3-button {:href "#"} [:i.fa.fa-envelope]]
     [:a.w3-bar-item.w3-button {:href "#"} [:i.fa.fa-user]]
     [:a.w3-bar-item.w3-button {:href "#"} [:i.fa.fa-cog]]
     ]] [:hr]
   [:div.w3-container [:h5 "Dashboard"]]
   [:div.w3-bar-block
    [:a.w3-bar-item.w3-button.w3-padding-16.w3-hide-large.w3-dark-grey.w3-hover-black
     {:href "#" :onclick "w3_close()" :title "close menu"}
     [:i.fa.fa-remove.fa-fw]
     "Close Menu"]
    [:a.w3-bar-item.w3-button.w3-padding.w3-blue
     {:href "#"} [:i.fa.fa-users.fa-fw] " Overview"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-eye.fa-fw] " Views"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-users.fa-fw] " Traffic"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-bullseye.fa-fw] " Geo"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-diamond.fa-fw] " Orders"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-bell.fa-fw] " News"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-bank.fa-fw] " General"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-history.fa-fw] " History"]
    [:a.w3-bar-item.w3-button.w3-padding
     {:href "#"} [:i.fa.fa-cog.fa-fw] " Settings"]
    ]]
  )

(def dash-1
  [:div.w3-row-padding.w3-margin-bottom
   [:div.w3-quarter
    [:div.w3-container.w3-red.w3-padding-16
     [:div.w3-left [:i.fa.fa-comment.w3-xxxlarge]]
     [:div.w3-right [:h3 "52"]]
     [:div.w3-clear]
     [:h4 "Messages"]]]
   [:div.w3-quarter
    [:div.w3-container.w3-blue.w3-padding-16
     [:div.w3-left [:i.fa.fa-eye.w3-xxxlarge]]
     [:div.w3-right [:h3 "99"]]
     [:div.w3-clear]
     [:h4 "Views"]]]
   [:div.w3-quarter
    [:div.w3-container.w3-teal.w3-padding-16
     [:div.w3-left [:i.fa.fa-share-alt.w3-xxxlarge]]
     [:div.w3-right [:h3 "23"]]
     [:div.w3-clear]
     [:h4 "Shares"]]]
   [:div.w3-quarter
    [:div.w3-container.w3-orange.w3-text-white.w3-padding-16
     [:div.w3-left [:i.fa.fa-users.w3-xxxlarge]]
     [:div.w3-right [:h3 "50"]]
     [:div.w3-clear]
     [:h4 "Users"]]]])

(def regions
  [:div.w3-third
   [:h5 "Regions"]
   [:img {:src "/w3images/region.jpg", :style "width:100%", :alt "Google Regional Map"}]])

(def feeds
  [:div.w3-twothird
   [:h5 "Feeds"]
   [:table.w3-table.w3-striped.w3-white
    [:tbody
     [:tr
      [:td [:i.fa.fa-user.w3-text-blue.w3-large]]
      [:td "New record, over 90 views."]
      [:td [:i "10 mins"]]]
     [:tr
      [:td [:i.fa.fa-bell.w3-text-red.w3-large]]
      [:td "Database error."]
      [:td [:i "15 mins"]]]
     [:tr
      [:td [:i.fa.fa-users.w3-text-yellow.w3-large]]
      [:td "New record, over 40 users."]
      [:td [:i "17 mins"]]]
     [:tr
      [:td [:i.fa.fa-comment.w3-text-red.w3-large]]
      [:td "New comments."]
      [:td [:i "25 mins"]]]
     [:tr
      [:td [:i.fa.fa-bookmark.w3-text-blue.w3-large]]
      [:td "Check transactions."]
      [:td [:i "28 mins"]]]
     [:tr
      [:td [:i.fa.fa-laptop.w3-text-red.w3-large]]
      [:td "CPU overload."]
      [:td [:i "35 mins"]]]
     [:tr
      [:td [:i.fa.fa-share-alt.w3-text-green.w3-large]]
      [:td "New shares."]
      [:td [:i "39 mins"]]]]]])

(def general-stats
  [:div.w3-container
   [:h5 "General Stats"]
   [:p "New Visitors"]
   [:div.w3-grey
    [:div.w3-container.w3-center.w3-padding.w3-green
     {:style "width:25%"} "+25%"]]
   [:p "New Users"]
   [:div.w3-grey
    [:div.w3-container.w3-center.w3-padding.w3-orange
     {:style "width:50%"} "50%"]]
   [:p "Bounce Rate"]
   [:div.w3-grey
    [:div.w3-container.w3-center.w3-padding.w3-red {:style "width:75%"} "75%"]]])

(def countries
  [:div.w3-container
   [:h5 "Countries"]
   [:table.w3-table.w3-striped.w3-bordered.w3-border.w3-hoverable.w3-white
    [:tbody
     [:tr [:td "United States"] [:td "65%"]]
     [:tr [:td "UK"] [:td "15.7%"]]
     [:tr [:td "Russia"] [:td "5.6%"]]
     [:tr [:td "Spain"] [:td "2.1%"]]
     [:tr [:td "India"] [:td "1.9%"]]
     [:tr [:td "France"] [:td "1.5%"]]]]
   [:br]
   [:button.w3-button.w3-dark-grey "More Countries  " [:i.fa.fa-arrow-right]]])

(def recent-users
  [:div.w3-container
   [:h5 "Recent Users"]
   [:ul.w3-ul.w3-card-4.w3-white
    [:li.w3-padding-16
     [:img.w3-left.w3-circle.w3-margin-right
      {:src "/w3images/avatar2.png", :style "width:35px"}]
     [:span.w3-xlarge "Mike"]
     [:br]]
    [:li.w3-padding-16
     [:img.w3-left.w3-circle.w3-margin-right
      {:src "/w3images/avatar5.png", :style "width:35px"}]
     [:span.w3-xlarge "Jill"]
     [:br]]
    [:li.w3-padding-16
     [:img.w3-left.w3-circle.w3-margin-right
      {:src "/w3images/avatar6.png", :style "width:35px"}]
     [:span.w3-xlarge "Jane"]
     [:br]]]])

(def recent-comments
  [:div.w3-container
   [:h5 "Recent Comments"]
   [:div.w3-row
    [:div.w3-col.m2.text-center
     [:img.w3-circle {:src "/w3images/avatar3.png",
                      :style "width:96px;height:96px"}]]
    [:div.w3-col.m10.w3-container
     [:h4 "John "
      [:span.w3-opacity.w3-medium "Sep 29, 2014, 9:12 PM"]]
     [:p (str "Keep up the GREAT work! I am cheering for you!! Lorem ipsum dolor"
              " sit amet, consectetur adipiscing elit, sed do eiusmod tempor"
              " incididunt ut labore et dolore magna aliqua.")]
     [:br]]]
   [:div.w3-row
    [:div.w3-col.m2.text-center
     [:img.w3-circle {:src "/w3images/avatar1.png",
                      :style "width:96px;height:96px"}]]
    [:div.w3-col.m10.w3-container
     [:h4 "Bo "
      [:span.w3-opacity.w3-medium "Sep 28, 2014, 10:15 PM"]]
     [:p "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."]
     [:br]]]])

(def last-panel
  [:div.w3-container.w3-dark-grey.w3-padding-32
   [:div.w3-row
    [:div.w3-container.w3-third
     [:h5.w3-bottombar.w3-border-green "Demographic"]
     [:p "Language"] [:p "Country"] [:p "City"]]
    [:div.w3-container.w3-third
     [:h5.w3-bottombar.w3-border-red "System"]
     [:p "Browser"] [:p "OS"] [:p "More"]]
    [:div.w3-container.w3-third
     [:h5.w3-bottombar.w3-border-orange "Target"]
     [:p "Users"] [:p "Active"] [:p "Geo"] [:p "Interests"]]]])

(defn page [csrf-token]
  (p/html5
   [:html {:lang "en"}
    (head csrf-token)
    [:body.w3-light-grey
     ;; Top container
     top-container
     ;; Sidebar/menu
     sidebar-menu
     ;; Overlay effect when opening sidebar on small screens
     [:div#myOverlay.w3-overlay.w3-hide-large.w3-animate-opacity
      {:onclick "w3_close()", :style "cursor:pointer", :title "close side menu"}]
     ;; Page Content!
     [:div.w3-main {:style "margin-left:300px;margin-top:43px;"}
      ;; Header
      [:header.w3-container {:style "padding-top:22px"}
       [:h5 [:b [:i.fa.fa-dashboard] " My Dashboard"]]]
      dash-1
      [:div {:class "w3-panel"}
       [:div {:class "w3-row-padding", :style "margin:0 -16px"}
        regions
        feeds]]
      [:hr]
      general-stats
      [:hr]
      countries
      [:hr]
      recent-users
      [:hr]
      recent-comments
      [:br]
      last-panel
      ;; footer
      [:footer.w3-container.w3-padding-16.w3-light-grey
       [:h4 "FOOTER"]
       [:p "Powered by "
        [:a {:href "https://www.w3schools.com/w3css/default.asp", :target "_blank"}
         "w3.css"]]]]
     [:script "// Get the Sidebar\nvar mySidebar = document.getElementById(\"mySidebar\");\n\n// Get the DIV with overlay effect\nvar overlayBg = document.getElementById(\"myOverlay\");\n\n// Toggle between showing and hiding the sidebar, and add overlay effect\nfunction w3_open() {\n  if (mySidebar.style.display === 'block') {\n    mySidebar.style.display = 'none';\n    overlayBg.style.display = \"none\";\n  } else {\n    mySidebar.style.display = 'block';\n    overlayBg.style.display = \"block\";\n  }\n}\n\n// Close the sidebar with the close button\nfunction w3_close() {\n  mySidebar.style.display = \"none\";\n  overlayBg.style.display = \"none\";\n}"]
     ]]))

(comment
  (page "hi")

  to-uri
  )
