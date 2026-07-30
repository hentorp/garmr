#![allow(clippy::float_arithmetic)]

//! The GeoParquet **`geo` file metadata** document.
//!
//! Per the [GeoParquet specification](https://geoparquet.org/releases/v1.1.0/) a
//! GeoParquet file "MUST include a `geo` key in the Parquet metadata" whose value
//! is a JSON-encoded UTF-8 string. Three fields are required — `version`,
//! `primary_column`, `columns` — and each geometry column MUST carry `encoding`
//! and `geometry_types`.
//!
//! Two spec details this module gets deliberately right:
//!
//! * **`crs` is PROJJSON, not a string.** The spec says the CRS "should be
//!   provided in PROJJSON format" and that omitting it means the default
//!   `OGC:CRS84` (longitude/latitude on WGS84). OSM coordinates *are* OGC:CRS84,
//!   so the correct encoding is to **omit the key**. Emitting the bare string
//!   `"EPSG:4326"` (as this module used to) is not valid PROJJSON and readers are
//!   entitled to reject it.
//! * **`bbox` is an array or absent.** `"bbox": null` is not a legal value; a
//!   file-level bbox we do not know is simply left out.
//!
//! [`GeoMeta`] additionally emits the 1.1 **`covering`** object, which is what
//! lets a reader prune row groups by min/max statistics on four plain numeric
//! columns instead of decoding WKB. See `.nornir/geoparquet-spatial-layout-design.md`.

/// Name of the file-level Parquet key-value metadata entry the spec mandates.
pub const GEO_KEY: &str = "geo";

/// The GeoParquet version this crate writes.
pub const GEO_VERSION: &str = "1.1.0";

/// Default name of the covering bounding-box struct column (`bbox`), matching
/// the spec's own example and Overture Maps' published layout.
pub const BBOX_COLUMN: &str = "bbox";

/// A builder for the `geo` metadata document.
///
/// ```
/// let json = osm_katana::metadata::GeoMeta::new(&["Point"])
///     .with_bbox([17.0, 59.0, 19.0, 60.0])
///     .with_covering("bbox")
///     .to_json();
/// assert!(json.contains("\"covering\""));
/// ```
#[derive(Clone, Debug)]
pub struct GeoMeta<'a> {
    primary_column: &'a str,
    geometry_types: &'a [&'a str],
    bbox: Option<[f64; 4]>,
    covering: Option<&'a str>,
}

impl<'a> GeoMeta<'a> {
    /// A minimal, spec-conformant document for a WKB `geometry` column holding
    /// `geometry_types`.
    pub fn new(geometry_types: &'a [&'a str]) -> Self {
        Self {
            primary_column: "geometry",
            geometry_types,
            bbox: None,
            covering: None,
        }
    }

    /// Declare the file-level bounding box `[xmin, ymin, xmax, ymax]`.
    pub fn with_bbox(mut self, bbox: [f64; 4]) -> Self {
        self.bbox = Some(bbox);
        self
    }

    /// Declare a GeoParquet 1.1 `covering.bbox` pointing at the struct column
    /// `column`, whose children MUST be named `xmin, ymin, xmax, ymax` in that
    /// order and be FLOAT or DOUBLE.
    pub fn with_covering(mut self, column: &'a str) -> Self {
        self.covering = Some(column);
        self
    }

    /// Render the JSON document.
    pub fn to_json(&self) -> String {
        let types = self
            .geometry_types
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut col = format!(r#""encoding":"WKB","geometry_types":[{types}]"#);
        if let Some([w, s, e, n]) = self.bbox {
            col.push_str(&format!(r#","bbox":[{w},{s},{e},{n}]"#));
        }
        if let Some(c) = self.covering {
            col.push_str(&format!(
                r#","covering":{{"bbox":{{"xmin":["{c}","xmin"],"ymin":["{c}","ymin"],"xmax":["{c}","xmax"],"ymax":["{c}","ymax"]}}}}"#
            ));
        }
        format!(
            r#"{{"version":"{GEO_VERSION}","primary_column":"{}","columns":{{"{}":{{{col}}}}}}}"#,
            self.primary_column, self.primary_column,
        )
    }
}

/// Back-compatible shorthand: the `geo` document for a WKB geometry column of
/// `geometry_types`, with an optional file-level bbox.
///
/// Kept as the existing call surface across `writer.rs`; new call sites that want
/// a `covering` use [`GeoMeta`] directly.
pub fn geo_metadata(geometry_types: &[&str], bbox: Option<[f64; 4]>) -> String {
    let mut m = GeoMeta::new(geometry_types);
    if let Some(b) = bbox {
        m = m.with_bbox(b);
    }
    m.to_json()
}

/// The `covering.bbox` column name declared in a `geo` document, if any.
///
/// Returns the struct column name (e.g. `"bbox"`) — the four leaf paths are then
/// `<name>.xmin`, `<name>.ymin`, `<name>.xmax`, `<name>.ymax`. Used by
/// [`crate::digest`] to exclude the *derived* covering column from the content
/// digest (it is a pure function of the geometry, so it carries no independent
/// content and including it would break comparability across a repack).
pub fn covering_column(geo_json: &str) -> Option<String> {
    let cov = geo_json.find("\"covering\"")?;
    let bbox = geo_json[cov..].find("\"xmin\"")?;
    let rest = &geo_json[cov + bbox..];
    let open = rest.find('[')?;
    let q1 = rest[open..].find('"')? + open + 1;
    let q2 = rest[q1..].find('"')? + q1;
    Some(rest[q1..q2].to_string())
}

#[cfg(test)]
mod tests {
    use super::{GeoMeta, covering_column, geo_metadata};
    use serde_json::{Value, json};

    /// Point layer, nothing optional: assert the full `geo` document parses to
    /// exactly the expected structure. RED if a field name, nesting or value
    /// drifts — in particular if the invalid `"crs":"EPSG:4326"` string or the
    /// invalid `"bbox":null` ever come back.
    #[test]
    fn point_minimal_matches_expected_json() {
        let s = geo_metadata(&["Point"], None);
        let got: Value = serde_json::from_str(&s).expect("geo_metadata must emit valid JSON");
        let expected = json!({
            "version": "1.1.0",
            "primary_column": "geometry",
            "columns": { "geometry": { "encoding": "WKB", "geometry_types": ["Point"] } }
        });
        assert_eq!(got, expected);
        // Spec conformance, stated as its own assertions so a regression names itself.
        assert!(
            got["columns"]["geometry"].get("crs").is_none(),
            "crs MUST be omitted (⇒ OGC:CRS84); a bare 'EPSG:4326' string is not PROJJSON"
        );
        assert!(
            got["columns"]["geometry"].get("bbox").is_none(),
            "bbox MUST be an array or absent — never null"
        );
    }

    /// Multi-geometry layer WITH a file-level bbox.
    #[test]
    fn multi_type_with_bbox_matches_expected_json() {
        let s = geo_metadata(
            &["LineString", "Polygon"],
            Some([10.5, -20.25, 30.75, 40.125]),
        );
        let got: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(
            got["columns"]["geometry"]["geometry_types"],
            json!(["LineString", "Polygon"])
        );
        assert_eq!(
            got["columns"]["geometry"]["bbox"],
            json!([10.5, -20.25, 30.75, 40.125])
        );
    }

    /// The 1.1 `covering.bbox` object must have exactly the spec's shape:
    /// `{"xmin": ["<col>", "xmin"], …}` for all four corners, in that order.
    #[test]
    fn covering_matches_spec_shape() {
        let s = GeoMeta::new(&["Point"]).with_covering("bbox").to_json();
        let got: Value = serde_json::from_str(&s).expect("valid JSON");
        let cov = &got["columns"]["geometry"]["covering"]["bbox"];
        assert_eq!(cov["xmin"], json!(["bbox", "xmin"]));
        assert_eq!(cov["ymin"], json!(["bbox", "ymin"]));
        assert_eq!(cov["xmax"], json!(["bbox", "xmax"]));
        assert_eq!(cov["ymax"], json!(["bbox", "ymax"]));
        assert_eq!(got["version"], json!("1.1.0"));
        // …and the extractor the digest relies on must find it.
        assert_eq!(covering_column(&s).as_deref(), Some("bbox"));
        // RED-when-broken: a document WITHOUT a covering must yield None, or the
        // digest would silently skip a real column.
        assert_eq!(covering_column(&geo_metadata(&["Point"], None)), None);
    }
}
