//! Whether a point lies inside a granted area (GW11, GW16).
//!
//! Only what the write guard actually needs: a polygon from the grant's `geoQ`, a point
//! from the entity's own `location`, and the question whether the one contains the other.
//! Anything the parser does not recognise — a geometry that is not a polygon, a location
//! that is not a point, a malformed coordinate list — answers "cannot tell", and the
//! caller turns that into a refusal, because a geo check that cannot decide must not pass.

use serde_json::Value;

/// A closed ring of `(longitude, latitude)` pairs, GeoJSON order.
type Ring = Vec<(f64, f64)>;

/// The outer ring and holes of a polygon, as GeoJSON orders them.
#[derive(Debug, Clone, PartialEq)]
pub struct Polygon {
    outer: Ring,
    holes: Vec<Ring>,
}

impl Polygon {
    /// Whether the point lies inside the polygon and outside all of its holes.
    ///
    /// Ray casting: count the edges a ray from the point crosses. A point exactly on an
    /// edge counts as inside, because a boundary case must not silently reject a write on
    /// a district border.
    pub fn contains(&self, point: (f64, f64)) -> bool {
        if !ring_contains(&self.outer, point) {
            return false;
        }
        !self.holes.iter().any(|hole| ring_contains(hole, point))
    }
}

/// The polygon of an NGSI-LD `geoQ`, or `None` when it is not a `within` polygon.
///
/// A `geoQ` is `georel=within;geometry=Polygon;coordinates=[[[lon,lat],…]]`. A relation
/// other than `within` is not a containment check, so this answers `None` rather than
/// guessing what it means.
pub fn granted_polygon(geo_q: &str) -> Option<Polygon> {
    let mut georel = None;
    let mut geometry = None;
    let mut coordinates = None;

    for part in geo_q.split(';') {
        match part.split_once('=') {
            Some(("georel", value)) => georel = Some(value.trim()),
            Some(("geometry", value)) => geometry = Some(value.trim()),
            Some(("coordinates", value)) => coordinates = Some(value.trim()),
            _ => {}
        }
    }

    if georel? != "within" || !geometry?.eq_ignore_ascii_case("Polygon") {
        return None;
    }
    polygon_from(&serde_json::from_str(coordinates?).ok()?)
}

/// The polygon of a GeoJSON `coordinates` array: an outer ring and any holes.
pub fn polygon_from(coordinates: &Value) -> Option<Polygon> {
    let rings: Vec<Ring> = coordinates
        .as_array()?
        .iter()
        .map(ring_from)
        .collect::<Option<Vec<Ring>>>()?;
    let mut rings = rings.into_iter();
    Some(Polygon {
        outer: rings.next()?,
        holes: rings.collect(),
    })
}

fn ring_from(ring: &Value) -> Option<Ring> {
    ring.as_array()?
        .iter()
        .map(|pair| {
            let pair = pair.as_array()?;
            Some((pair.first()?.as_f64()?, pair.get(1)?.as_f64()?))
        })
        .collect()
}

/// The coordinates of an entity's `location`, or `None` when it has none or it is not a
/// point (GW16).
pub fn entity_point(entity: &Value) -> Option<(f64, f64)> {
    let location = entity.get("location")?;
    // NGSI-LD wraps a GeoProperty value; a plain GeoJSON object is accepted too, because
    // that is what a normalized and a simplified payload look like respectively.
    let geometry = location.get("value").unwrap_or(location);
    if !geometry
        .get("type")?
        .as_str()?
        .eq_ignore_ascii_case("Point")
    {
        return None;
    }
    let coordinates = geometry.get("coordinates")?.as_array()?;
    Some((
        coordinates.first()?.as_f64()?,
        coordinates.get(1)?.as_f64()?,
    ))
}

/// Ray casting with the boundary counted as inside.
fn ring_contains(ring: &[(f64, f64)], (x, y): (f64, f64)) -> bool {
    if ring.len() < 3 {
        return false;
    }

    let mut inside = false;
    for window in 0..ring.len() {
        let (x1, y1) = ring[window];
        let (x2, y2) = ring[(window + 1) % ring.len()];

        if on_segment((x1, y1), (x2, y2), (x, y)) {
            return true;
        }
        // The half-open rule on y keeps a vertex from being counted twice.
        if (y1 > y) != (y2 > y) {
            let crossing = (x2 - x1) * (y - y1) / (y2 - y1) + x1;
            if x < crossing {
                inside = !inside;
            }
        }
    }
    inside
}

/// Whether the point lies on the segment, within the tolerance a coordinate carries.
fn on_segment((x1, y1): (f64, f64), (x2, y2): (f64, f64), (x, y): (f64, f64)) -> bool {
    const EPSILON: f64 = 1e-12;
    let cross = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1);
    if cross.abs() > EPSILON {
        return false;
    }
    x >= x1.min(x2) - EPSILON
        && x <= x1.max(x2) + EPSILON
        && y >= y1.min(y2) - EPSILON
        && y <= y1.max(y2) + EPSILON
}
