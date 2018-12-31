(ns cawala.server-components.geo-spatial
  (:require [geo [geohash :as geohash] [jts :as jts] [spatial :as spatial]
            [io :as gio]]))

(comment
  (spatial/earth-radius spatial/south-pole)
  (spatial/earth-radius (spatial/geohash-point 45 0))
  (def lhr (spatial/spatial4j-point 51.477500 -0.461388))
  (def lax (spatial/spatial4j-point 33.942495 -118.408067))
  (/ (spatial/distance lhr lax) 1000)
  (def london (spatial/spatial4j-point 51.5072 0.1275))
  (spatial/intersects? lhr (spatial/circle london 50000))
  (spatial/intersects? lhr (spatial/circle london 10000))
  (-> london (spatial/circle 50) geohash/shape->precision)
  (def h (-> london (geohash/geohash 35)))
  h
  (geohash/geohash-midline-dimensions h)
  (geohash/string h)
  (spatial/intersects? (geohash/geohash "u10j4") london)
  (spatial/relate (geohash/geohash "u10j4bs") (geohash/geohash "u10j4"))
  (spatial/relate (geohash/geohash "u10j4") (geohash/geohash "u10j4bs"))
  (spatial/relate h (geohash/northern-neighbor h))
  (-> (iterate geohash/northern-neighbor h) (nth 5) (spatial/relate h))
  (-> lhr (spatial/circle 1000) (geohash/geohashes-intersecting 30)
      (->> (map geohash/string)))
  (map geohash/string (geohash/geohashes-near lhr 1000 30))
  (gio/read-geojson "{\"type\":\"Feature\",\"geometry\":{\"type\":\"Point\",\"coordinates\":[0.0,0.0]},\"properties\":{\"name\":\"null island\"}}")
  (->> "{\"type\":\"Polygon\",\"coordinates\":[[[-70.0,30.0],[-70.0,31.0],[-71.0,31.0],[-71.0,30.0],[-70.0,30.0]]]}"
       gio/read-geojson
       (map :geometry)
       )
  (def gj (slurp "/home/paul/Dropbox/cape-breton.geojson"))
  (def geoms (gio/read-geojson gj))
  (count geoms)
  (first geoms)
  (-> geoms first :geometry .getLength)

  )
