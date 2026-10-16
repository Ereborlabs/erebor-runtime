use std::any::Any;
use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, Decimal256Array, LargeStringArray, StringArray, StringViewArray,
};
use datafusion::arrow::compute::{cast, cast_with_options, CastOptions};
use datafusion::arrow::datatypes::{i256, DataType};
use datafusion::common::{exec_err, plan_err, Result, ScalarValue};
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct HugeInt {
    signature: Signature,
    try_cast: bool,
}

impl HugeInt {
    pub(super) fn functions() -> Vec<Arc<ScalarUDF>> {
        let mut functions = [false, true]
            .map(|try_cast| {
                Arc::new(ScalarUDF::from(Self {
                    signature: Signature::any(1, Volatility::Immutable),
                    try_cast,
                }))
            })
            .to_vec();
        functions.extend([true, false].map(|input| {
            Arc::new(ScalarUDF::from(SumValue {
                signature: Signature::any(1, Volatility::Immutable),
                input,
            }))
        }));
        functions
    }

    fn convert(&self, source: &ArrayRef) -> Result<ArrayRef> {
        let strings = match source.data_type() {
            DataType::Utf8 => source
                .as_any()
                .downcast_ref::<StringArray>()
                .map(|array| array.iter().collect::<Vec<_>>()),
            DataType::LargeUtf8 => source
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .map(|array| array.iter().collect::<Vec<_>>()),
            DataType::Utf8View => source
                .as_any()
                .downcast_ref::<StringViewArray>()
                .map(|array| array.iter().collect::<Vec<_>>()),
            _ => None,
        };
        let values = if let Some(strings) = strings {
            strings.into_iter().map(|value| match value {
                None => Ok(None),
                Some(value) => match Self::text(value) {
                    Some(value) => Ok(Some(i256::from_i128(value))),
                    None if self.try_cast => Ok(None),
                    None => exec_err!("HUGEINT cast is outside the signed 128-bit range or has invalid syntax"),
                },
            }).collect::<Result<Vec<_>>>()?
        } else {
            let source = if source.data_type() == &DataType::Boolean {
                cast(source, &DataType::Int8)?
            } else {
                source.clone()
            };
            let converted = cast_with_options(
                &source,
                &DataType::Decimal256(39, 0),
                &CastOptions {
                    safe: self.try_cast,
                    ..Default::default()
                },
            )?;
            let converted = converted
                .as_any()
                .downcast_ref::<Decimal256Array>()
                .ok_or_else(|| {
                    datafusion::common::DataFusionError::Execution(
                        "HUGEINT cast returned an invalid array".into(),
                    )
                })?;
            converted
                .iter()
                .map(|value| match value {
                    Some(value) if value.to_i128().is_none() && self.try_cast => Ok(None),
                    Some(value) if value.to_i128().is_none() => {
                        exec_err!("HUGEINT cast is outside the signed 128-bit range")
                    }
                    value => Ok(value),
                })
                .collect::<Result<Vec<_>>>()?
        };
        Ok(Arc::new(
            Decimal256Array::from(values).with_precision_and_scale(39, 0)?,
        ))
    }

    fn text(value: &str) -> Option<i128> {
        let value = value.trim_ascii();
        let radix = if value.starts_with("0x") || value.starts_with("0X") {
            16
        } else if value.starts_with("0b") || value.starts_with("0B") {
            2
        } else {
            10
        };
        let digits = if radix == 10 { value } else { value.get(2..)? };
        for (index, byte) in digits.bytes().enumerate() {
            if byte == b'_'
                && (index == 0
                    || !digits.as_bytes().get(index - 1)?.is_ascii_hexdigit()
                    || !digits.as_bytes().get(index + 1)?.is_ascii_hexdigit()
                    || radix == 10
                        && (!digits.as_bytes()[index - 1].is_ascii_digit()
                            || !digits.as_bytes()[index + 1].is_ascii_digit()))
            {
                return None;
            }
        }
        let normalized = digits.replace('_', "");
        if radix != 10 {
            if !normalized.bytes().all(|byte| match radix {
                16 => byte.is_ascii_hexdigit(),
                _ => matches!(byte, b'0' | b'1'),
            }) {
                return None;
            }
            return i128::from_str_radix(&normalized, radix).ok();
        }
        let (mantissa, exponent) =
            if let Some((mantissa, exponent)) = normalized.split_once(['e', 'E']) {
                (mantissa, exponent.parse::<i16>().ok()?)
            } else {
                (normalized.as_str(), 0)
            };
        let negative = mantissa.starts_with('-');
        let mantissa = mantissa.strip_prefix(['-', '+']).unwrap_or(mantissa);
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if whole.is_empty() && fraction.is_empty()
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let integer = if whole.is_empty() {
            0
        } else {
            whole.parse::<u128>().ok()?
        };
        if integer > (i128::MAX as u128) + u128::from(negative) {
            return None;
        }
        let point = i64::try_from(whole.len()).ok()? + i64::from(exponent);
        let mut result = 0_i128;
        let mut digits = whole.bytes().chain(fraction.bytes());
        for _ in 0..point.max(0) {
            let digit = i128::from(digits.next().unwrap_or(b'0') - b'0');
            result = if negative {
                result.checked_mul(10)?.checked_sub(digit)?
            } else {
                result.checked_mul(10)?.checked_add(digit)?
            };
        }
        if point >= 0 && digits.next().is_some_and(|digit| digit >= b'5') {
            result = if negative {
                result.checked_sub(1)?
            } else {
                result.checked_add(1)?
            };
        }
        Some(result)
    }
}

impl ScalarUDFImpl for HugeInt {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        if self.try_cast {
            "__araphor_try_hugeint"
        } else {
            "__araphor_hugeint"
        }
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, types: &[DataType]) -> Result<DataType> {
        if types.len() != 1
            || !(types[0].is_numeric()
                || matches!(
                    types[0],
                    DataType::Boolean
                        | DataType::Null
                        | DataType::Utf8
                        | DataType::LargeUtf8
                        | DataType::Utf8View
                ))
        {
            return plan_err!("HUGEINT cast requires a number, boolean, or text");
        }
        Ok(DataType::Decimal256(39, 0))
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
        let arrays = ColumnarValue::values_to_arrays(&args.args)?;
        let Some(source) = arrays.first().filter(|_| arrays.len() == 1) else {
            return exec_err!("HUGEINT cast requires one argument");
        };
        let result = self.convert(source)?;
        if matches!(args.args.as_slice(), [ColumnarValue::Scalar(_)]) {
            Ok(ColumnarValue::Scalar(ScalarValue::try_from_array(
                &result, 0,
            )?))
        } else {
            Ok(ColumnarValue::Array(result))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct SumValue {
    signature: Signature,
    input: bool,
}

impl ScalarUDFImpl for SumValue {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        if self.input {
            "__araphor_sum_input"
        } else {
            "__araphor_sum_result"
        }
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, types: &[DataType]) -> Result<DataType> {
        let [kind] = types else {
            return plan_err!("SUM requires one numeric argument");
        };
        if !self.input {
            return Ok(if kind == &DataType::Decimal256(49, 0) {
                DataType::Decimal256(39, 0)
            } else {
                kind.clone()
            });
        }
        Ok(match kind {
            DataType::Boolean | DataType::Null => DataType::Decimal256(29, 0),
            kind if kind.is_integer() => DataType::Decimal256(29, 0),
            kind if kind.is_floating() => DataType::Float64,
            DataType::Decimal256(39, 0) => kind.clone(),
            DataType::Decimal32(_, scale)
            | DataType::Decimal64(_, scale)
            | DataType::Decimal128(_, scale) => DataType::Decimal128(38, *scale),
            _ => return plan_err!("SUM requires a numeric argument"),
        })
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
        if !self.input {
            let [source] = args.args.as_slice() else {
                return exec_err!("SUM result requires one argument");
            };
            if source.data_type() != DataType::Decimal256(49, 0) {
                return Ok(source.clone());
            }
        }
        let arrays = ColumnarValue::values_to_arrays(&args.args)?;
        let Some(source) = arrays.first().filter(|_| arrays.len() == 1) else {
            return exec_err!("SUM requires one argument");
        };
        let source = if source.data_type() == &DataType::Boolean {
            cast(source, &DataType::Int8)?
        } else {
            source.clone()
        };
        let result = if self.input {
            cast_with_options(
                &source,
                args.return_type(),
                &CastOptions {
                    safe: false,
                    ..Default::default()
                },
            )?
        } else {
            HugeInt {
                signature: self.signature.clone(),
                try_cast: false,
            }
            .convert(&source)?
        };
        if matches!(args.args.as_slice(), [ColumnarValue::Scalar(_)]) {
            Ok(ColumnarValue::Scalar(ScalarValue::try_from_array(
                &result, 0,
            )?))
        } else {
            Ok(ColumnarValue::Array(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{Float64Array, Int64Array};

    #[test]
    fn signed_text_and_rounding() {
        for (text, expected) in [
            (i128::MAX.to_string(), i128::MAX),
            (i128::MIN.to_string(), i128::MIN),
            ("1.5".into(), 2),
            ("-1.5".into(), -2),
            ("1e3".into(), 1000),
            ("-5e-1".into(), -1),
            ("  +1_000.5  ".into(), 1001),
            (format!("{}.4", i128::MAX), i128::MAX),
            (format!("{}e0", i128::MAX), i128::MAX),
        ] {
            assert_eq!(HugeInt::text(&text), Some(expected), "{text}");
        }
        for text in [
            format!("{}.5", i128::MAX),
            format!("{}0", i128::MAX),
            "1__0".into(),
            "1e99999999".into(),
            "bad".into(),
        ] {
            assert_eq!(HugeInt::text(&text), None, "{text}");
        }
    }

    #[test]
    fn numeric_casts_and_try_cast() -> Result<()> {
        let cast = HugeInt {
            signature: Signature::any(1, Volatility::Immutable),
            try_cast: false,
        };
        let source: ArrayRef =
            Arc::new(Int64Array::from(vec![Some(i64::MAX), None, Some(i64::MIN)]));
        let result = cast.convert(&source)?;
        assert_eq!(
            result
                .as_any()
                .downcast_ref::<Decimal256Array>()
                .map(|array| array.iter().collect::<Vec<_>>()),
            Some(vec![
                Some(i256::from_i128(i128::from(i64::MAX))),
                None,
                Some(i256::from_i128(i128::from(i64::MIN)))
            ])
        );
        let source: ArrayRef = Arc::new(
            Decimal256Array::from(vec![i256::from_i128(i128::MAX), i256::from_i128(i128::MIN)])
                .with_precision_and_scale(39, 0)?,
        );
        assert!(cast.convert(&source).is_ok());
        let overflow = i256::from_i128(i128::MAX)
            .checked_add(i256::ONE)
            .ok_or_else(|| {
                datafusion::common::DataFusionError::Execution("test overflow value".into())
            })?;
        let source: ArrayRef =
            Arc::new(Decimal256Array::from(vec![overflow]).with_precision_and_scale(39, 0)?);
        assert!(cast.convert(&source).is_err());
        let source: ArrayRef = Arc::new(Float64Array::from(vec![1.5, -1.5, f64::INFINITY]));
        assert!(cast.convert(&source).is_err());
        let cast = HugeInt {
            try_cast: true,
            ..cast
        };
        let result = cast.convert(&source)?;
        assert_eq!(
            result
                .as_any()
                .downcast_ref::<Decimal256Array>()
                .map(|array| array.iter().collect::<Vec<_>>()),
            Some(vec![
                Some(i256::from_i128(2)),
                Some(i256::from_i128(-2)),
                None
            ])
        );
        Ok(())
    }
}
