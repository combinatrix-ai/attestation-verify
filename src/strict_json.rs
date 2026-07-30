//! Strict JSON parsing: rejects duplicate object keys.
//!
//! `serde_json` silently lets the last occurrence of a duplicate object key
//! win, both when deserializing directly into a struct and when collecting
//! into a [`serde_json::Value`]. Once a `Value` tree has been built, the
//! information that a duplicate existed is already gone, so rejecting
//! duplicates has to happen during the initial parse, not as a later check
//! on the parsed tree.
//!
//! DESIGN.md "Core decisions" item 2 requires duplicate-key rejection as
//! part of hardened parsing. This module implements it once, generically,
//! with a custom [`Visitor`] that mirrors `serde_json::Value`'s own
//! deserialization but tracks the keys seen at each object nesting level
//! and errors on a repeat. Callers get back an ordinary `serde_json::Value`
//! on success and then use `serde_json::from_value` to extract typed data,
//! so field-level typing still goes through ordinary serde derive.
//!
//! Nesting depth is bounded by `serde_json`'s own recursion guard (128
//! levels by default): that limit is enforced inside the deserializer's own
//! object/array token parsing, independent of which `Visitor` is driving
//! it, so it applies here the same as it would to any other visitor.

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};

use crate::error::ParseError;

/// Parses `bytes` as JSON, rejecting duplicate object keys at any nesting
/// level and rejecting trailing bytes after the JSON value. Returns a plain
/// [`serde_json::Value`] on success, for further typed extraction via
/// `serde_json::from_value`.
pub(crate) fn parse_strict(bytes: &[u8]) -> Result<serde_json::Value, ParseError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = de
        .deserialize_any(StrictJsonVisitor)
        .map_err(|e| ParseError::Json(e.to_string()))?;
    de.end().map_err(|e| ParseError::Json(e.to_string()))?;
    Ok(value)
}

/// Zero-sized [`Visitor`] that rebuilds a [`serde_json::Value`] while
/// checking for duplicate object keys. Also implements [`DeserializeSeed`]
/// (delegating to `deserialize_any`) so it can be used as the seed for
/// recursive array/map elements, which is what makes the duplicate-key
/// check apply at every nesting level rather than just the top one.
#[derive(Clone, Copy)]
struct StrictJsonVisitor;

impl<'de> DeserializeSeed<'de> for StrictJsonVisitor {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(v).map_or_else(
            || Err(E::custom("JSON number is not finite")),
            |n| Ok(serde_json::Value::Number(n)),
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(v.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some(elem) = seq.next_element_seed(StrictJsonVisitor)? {
            out.push(elem);
        }
        Ok(serde_json::Value::Array(out))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            let value = map.next_value_seed(StrictJsonVisitor)?;
            out.insert(key, value);
        }
        Ok(serde_json::Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict;
    use crate::error::ParseError;

    #[test]
    fn accepts_well_formed_json() -> Result<(), Box<dyn std::error::Error>> {
        let value = parse_strict(br#"{"a":1,"b":[1,2,{"c":true}],"d":null,"e":1.5}"#)?;
        if value["a"] != 1 {
            return Err("field a did not round-trip".into());
        }
        if value["b"][2]["c"] != true {
            return Err("nested field c did not round-trip".into());
        }
        if !value["d"].is_null() {
            return Err("field d should be null".into());
        }
        Ok(())
    }

    #[test]
    fn rejects_top_level_duplicate_key() -> Result<(), Box<dyn std::error::Error>> {
        match parse_strict(br#"{"a":1,"a":2}"#) {
            Err(ParseError::Json(_)) => Ok(()),
            Err(other) => Err(format!("expected ParseError::Json, got {other:?}").into()),
            Ok(_) => Err("expected duplicate key to be rejected".into()),
        }
    }

    #[test]
    fn rejects_nested_object_duplicate_key() -> Result<(), Box<dyn std::error::Error>> {
        match parse_strict(br#"{"a":{"b":1,"b":2}}"#) {
            Err(ParseError::Json(_)) => Ok(()),
            Err(other) => Err(format!("expected ParseError::Json, got {other:?}").into()),
            Ok(_) => Err("expected nested duplicate key to be rejected".into()),
        }
    }

    #[test]
    fn rejects_duplicate_key_inside_array_element() -> Result<(), Box<dyn std::error::Error>> {
        match parse_strict(br#"{"a":[{"b":1,"b":2}]}"#) {
            Err(ParseError::Json(_)) => Ok(()),
            Err(other) => Err(format!("expected ParseError::Json, got {other:?}").into()),
            Ok(_) => Err("expected duplicate key inside array element to be rejected".into()),
        }
    }

    #[test]
    fn rejects_trailing_garbage() -> Result<(), Box<dyn std::error::Error>> {
        match parse_strict(br#"{"a":1} garbage"#) {
            Err(ParseError::Json(_)) => Ok(()),
            Err(other) => Err(format!("expected ParseError::Json, got {other:?}").into()),
            Ok(_) => Err("expected trailing garbage to be rejected".into()),
        }
    }

    #[test]
    fn rejects_truncated_json() -> Result<(), Box<dyn std::error::Error>> {
        match parse_strict(br#"{"a":"#) {
            Err(ParseError::Json(_)) => Ok(()),
            Err(other) => Err(format!("expected ParseError::Json, got {other:?}").into()),
            Ok(_) => Err("expected truncated JSON to be rejected".into()),
        }
    }
}
