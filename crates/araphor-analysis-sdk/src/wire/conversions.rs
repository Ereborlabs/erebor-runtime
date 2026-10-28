#[doc(hidden)]
#[macro_export]
macro_rules! __component_record {
    ($native:ty, $component:ty; [$($plain:ident),*]; [$($single:ident),*]; [$($optional:ident),*]; [$($list:ident),*]) => {
        impl From<$native> for $component {
            fn from(value: $native) -> Self {
                Self {
                    $($plain: value.$plain,)*
                    $($single: value.$single.into(),)*
                    $($optional: value.$optional.map(Into::into),)*
                    $($list: value.$list.into_iter().map(Into::into).collect(),)*
                }
            }
        }
        impl From<$component> for $native {
            fn from(value: $component) -> Self {
                Self {
                    $($plain: value.$plain,)*
                    $($single: value.$single.into(),)*
                    $($optional: value.$optional.map(Into::into),)*
                    $($list: value.$list.into_iter().map(Into::into).collect(),)*
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __component_enum {
    ($native:ty, $component:ty; $($variant:ident),*) => {
        impl From<$native> for $component {
            fn from(value: $native) -> Self {
                match value { $(<$native>::$variant => Self::$variant,)* }
            }
        }
        impl From<$component> for $native {
            fn from(value: $component) -> Self {
                match value { $(<$component>::$variant => Self::$variant,)* }
            }
        }
    };
}

/// Connect the generated WIT types to the SDK wire types.
#[macro_export]
macro_rules! component_conversions {
    ($types:path) => {
        use $types as component_types;

        $crate::__component_record!($crate::EvaluationContext, component_types::EvaluationContext;
            [id, time_utc_ns, seed]; []; []; []);
        $crate::__component_record!($crate::SourceWindow, component_types::SourceWindow;
            [source, start_utc_ns, end_utc_ns]; []; []; []);
        $crate::__component_record!($crate::Revision, component_types::Revision;
            [owner, id]; []; [window]; []);
        $crate::__component_enum!($crate::CoverageState, component_types::CoverageState;
            Complete, Gapped, Unknown);
        $crate::__component_record!($crate::Coverage, component_types::Coverage;
            [limits]; [state]; []; []);
        $crate::__component_record!($crate::wire::Dataset, component_types::Dataset;
            [name, arrow_ipc]; []; []; []);
        $crate::__component_record!($crate::wire::Input, component_types::Input;
            []; [data, revision, coverage]; []; []);
        $crate::__component_record!($crate::wire::Checkpoint, component_types::Checkpoint;
            [version]; []; []; [datasets]);
        $crate::__component_record!($crate::wire::Evaluation, component_types::Evaluation;
            [export_name, parameters]; [context]; [checkpoint]; [inputs, previous_outputs]);
        $crate::__component_record!($crate::RowRef, component_types::RowRef;
            [dataset, row]; []; []; []);
        $crate::__component_record!($crate::EvidenceLink, component_types::EvidenceLink;
            []; [output, input]; []; []);
        $crate::__component_record!($crate::wire::ReasonValue, component_types::ReasonValue;
            [code, details]; [output]; []; []);
        $crate::__component_record!($crate::wire::Output, component_types::Output;
            []; []; [checkpoint]; [datasets, evidence, reasons]);
        $crate::__component_enum!($crate::ErrorCode, component_types::ErrorCode;
            Invalid, Incompatible, Unauthorized, Incomplete, Failed, Limit);
        $crate::__component_record!($crate::wire::EvaluationError, component_types::EvaluationError;
            [field]; [code]; []; []);
    };
}
