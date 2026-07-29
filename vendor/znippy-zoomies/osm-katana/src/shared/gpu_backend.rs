#![allow(clippy::float_arithmetic, clippy::arithmetic_side_effects)]

pub struct RawCoord {
    pub lat: f32,
    pub lon: f32,
}

/// A way with resolved coordinates, ready for WKB encoding.
pub struct RawWay {
    /// (lon, lat) pairs in WGS-84 — original coordinate order.
    pub coords: Vec<(f64, f64)>,
    /// true → encode as Polygon exterior, false → encode as LineString.
    pub is_area: bool,
}

pub struct Bbox {
    pub min_x: f32,
    pub min_y: f32,
    pub max_x: f32,
    pub max_y: f32,
}

pub trait GpuBackend: Send + Sync {
    fn project_mercator(&self, coords: &[RawCoord]) -> Vec<(f32, f32)>;
    fn compute_bbox(&self, point_sets: &[Vec<(f32, f32)>]) -> Vec<Bbox>;
    fn encode_wkb(&self, ways: &[RawWay]) -> Vec<Option<Vec<u8>>>;
}

pub struct CpuBackend;

impl GpuBackend for CpuBackend {
    fn project_mercator(&self, coords: &[RawCoord]) -> Vec<(f32, f32)> {
        coords
            .iter()
            .map(|c| {
                let x = (c.lon + 180.0) / 360.0;
                let lat_r = c.lat.to_radians();
                let y = (1.0 - (lat_r.tan() + 1.0 / lat_r.cos()).ln() / std::f32::consts::PI) / 2.0;
                (x, y)
            })
            .collect()
    }

    fn compute_bbox(&self, point_sets: &[Vec<(f32, f32)>]) -> Vec<Bbox> {
        point_sets
            .iter()
            .map(|pts| {
                let mut min_x = f32::MAX;
                let mut min_y = f32::MAX;
                let mut max_x = f32::MIN;
                let mut max_y = f32::MIN;
                for &(x, y) in pts {
                    if x < min_x {
                        min_x = x;
                    }
                    if y < min_y {
                        min_y = y;
                    }
                    if x > max_x {
                        max_x = x;
                    }
                    if y > max_y {
                        max_y = y;
                    }
                }
                Bbox {
                    min_x,
                    min_y,
                    max_x,
                    max_y,
                }
            })
            .collect()
    }

    fn encode_wkb(&self, ways: &[RawWay]) -> Vec<Option<Vec<u8>>> {
        ways.iter()
            .map(|way| {
                if way.coords.len() < 2 {
                    return None;
                }
                Some(if way.is_area && way.coords.len() >= 4 {
                    wkb_polygon(&way.coords)
                } else {
                    wkb_linestring(&way.coords)
                })
            })
            .collect()
    }
}

fn wkb_linestring(coords: &[(f64, f64)]) -> Vec<u8> {
    let n = coords.len();
    let mut buf = Vec::with_capacity(9 + n * 16);
    buf.push(1u8);
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for &(x, y) in coords {
        buf.extend_from_slice(&x.to_le_bytes());
        buf.extend_from_slice(&y.to_le_bytes());
    }
    buf
}

fn wkb_polygon(exterior: &[(f64, f64)]) -> Vec<u8> {
    let n = exterior.len();
    let mut buf = Vec::with_capacity(13 + n * 16);
    buf.push(1u8);
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for &(x, y) in exterior {
        buf.extend_from_slice(&x.to_le_bytes());
        buf.extend_from_slice(&y.to_le_bytes());
    }
    buf
}
