# Security Rule And Aggregate Operations

This is the rule operation record for the
[Security Analytics contract inventory](security-contract-inventory.md).
All listed ports and reference checks belong to 7.5.9 and are **Not done**.
The input, output, state, and host rules in the parent inventory apply to every
row. The rule rows use `security.rules.evaluate`; aggregate rows use
`security.rules.aggregate`.

Source paths below are relative to
[`org/opensearch/securityanalytics`](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/).
The [source accounting report](security-source-accounting.tsv) records declared
helper symbols and local/external dependencies for each tracked file.

## Parsing, selectors, values, and mappings

| Operation ID | Source symbols | Exact requirement and result | State or delegated calculation |
| --- | --- | --- | --- |
| SA-01.parse | `SigmaRule.fromYaml`, `fromDict`; `RuleIndices.getQueries`; `Rule` constructor | YAML rule -> title, UUID, level, status, log source, date, description, author, tags, fields, false positives, conditions, and structured errors. Preserve source metadata. | Safe YAML parser; configured nesting limit. Rule revision is input. |
| SA-01.detections | `SigmaDetections.fromDict`; `SigmaDetection.fromDefinition`, `postProcess` | Map entries combine with AND; lists of detections combine with OR; scalar/keyword and field-bound detections retain their distinct meaning. A scalar or a list of conditions can produce multiple queries. | No durable state. Preserve list and map structure. |
| SA-01.condition | `SigmaCondition.parsed`, `convertArgs`; `ConditionTraverseVisitor`; `ConditionIdentifier.postProcess`; `ConditionItem.postProcess` | `not`, `and`, `or`, parentheses, and named detections. Grammar precedence is NOT, AND, OR. Resolve unknown identifiers as errors. | Generated ANTLR condition parser. |
| SA-01.selector-one | `ConditionSelector` constructor and `postProcess` | `1 of` and `any of` -> OR of matching detection names. | `them` selects all names; `*` in a name pattern becomes a full-match wildcard. |
| SA-01.selector-all | `ConditionSelector.postProcess` | `all of` -> AND of matching detection names. Include zero matched names as a reference case. | Same selector helper; source grammar admits 1/any/all only. |
| SA-01.values | `SigmaTypeFacade.sigmaType`; `SigmaDetectionItem.fromMapping`, `fromValue`, `postProcess`; `QueryBackend.convertConditionFieldEqVal`, `convertConditionVal` | Bound string, integer, float, Boolean, null, regex, CIDR, comparison, and expansion values. A value list is OR unless `all` changes it to AND. Unbound strings/numbers/regex use keyword semantics; an unbound Boolean is rejected. | Source numeric types are Java `int` and `float`. Other object classes map to null in `SigmaTypeFacade`; qualify this explicitly. |
| SA-01.strings | `SigmaString` constructor, `mergeStrings`, `append`, `prepend`, `convert`, `replaceWithPlaceholder`, `replacePlaceholders`, `containsPlaceholder` | Preserve wildcard `*` and `?`, escapes, spaces, reserved tokens, string fragments, placeholder expansion, byte conversion, and transformed-value ordering. | Java charset and query-string parser behavior. `containsSpecial`, `containsWildcard`, and prefix/suffix checks supply modifier preconditions. |
| SA-01.null | `OSQueryBackend.convertConditionFieldEqValNull`; `QueryBackend.convertConditionFieldEqValNot`; `OSQueryBackend.convertExistsField` | Source null expression uses `NOT [* TO *]`; field negation appends `_exists_`. Distinguish a missing field from a present null value in input. | OpenSearch indexed existence semantics. An `exists` modifier is not registered. |
| SA-01.boolean | `OSQueryBackend.convertConditionAnd`, `convertConditionOr`, `convertConditionNot`; `QueryBackend.decideConvertConditionAsInExpression` | Preserve Boolean grouping, De Morgan conversion, list expansion, NOT existence checks, and operator precedence. | Query rendering and OpenSearch evaluation. Same-field conversion optimization must not change results. |
| SA-01.bound | `OSQueryBackend.convertConditionFieldEqValStr`, `Num`, `Bool`, `Re`, `Cidr`, `OpVal` | Render/evaluate each bound type with exact field mapping, quoting, escaping, analyzer, and numeric comparison. | Source query fields use text/rule_analyzer, integer, float, or Boolean mapping. |
| SA-01.unbound | `OSQueryBackend.convertConditionValStr`, `Num`, `Re`; `QueryBackend.convertConditionValQueryExpansion` | Keyword scalar/regex searches and expansion OR. Preserve configured default fields and analyzer assumptions. | OpenSearch query-string defaults must become declared input semantics. |
| SA-01.mapping-tree | `MappingsTraverser.traverse`, `extractFlatNonAliasFields`; `Node` path, leaf, and alias methods | Nested mapping tree -> flat paths, leaves, alias pairs, and errors. Preserve skip-type and skip-property behavior. | Mapping metadata is pinned input, not a live cluster call. |
| SA-01.mapping-validation | `MapperUtils.getAllAliases`, `getAllAliasPathPairs`, `getAllPathsFromAliasMappings`, `validateIndexMappings`, `extractAllFieldsFlat`, `getAllNonAliasFieldsFromIndex`, `getAliasMappingsWithFilter`, `getFieldMappingsFlat` | Alias/schema definitions -> present/missing paths and selected type definitions. Reject empty mappings, missing alias paths, and wrong alias type where the source rejects them. | No package permission grant follows from an applicable mapping. |
| SA-01.mapping-merge | `LogTypeService.mergeFieldMappings`, `createFieldMappingDocs`, `getRuleFieldMappings`, `getRuleFieldMappingsAllSchemas`, `getRequiredFields`; `MapperService.filterNonApplicableAliases`, `shouldUpdateEcsMappingAndMaybeUpdates` | Built-in/custom field definitions -> selected schema mappings, merged raw-field/log-type entries, aliases, and required fields. Preserve schema selection and overwrite rules. | ECS and OCSF schema data are pinned inputs. Alias application itself stays in the host. |
| SA-01.applicability | `RuleValidator.validateRules`; `TransportIndexDetectorAction.resolveRuleFieldNamesAndUpsertMonitorFromQueries` | Every required rule field must be present under the selected aliases/schema. Return exact rule IDs and missing fields. | Input coverage and provenance stay with the host. Field absence cannot establish a negative finding. |
| SA-01.metadata | `SigmaLogSource.fromDict`; `SigmaRuleTag.fromStr`; `SigmaLevel`, `SigmaStatus`; `BuiltinLogTypeLoader`, `LogTypeService` | Parse source product/category/service, tag namespace/name, levels, statuses, log-type metadata, correlation IDs, and indicator field declarations. | Pinned source resource files. Serialization and storage do not create extra algorithm exports. |

The registered grammar is in
[Condition.g4](../../../../../security-analytics/src/main/grammars/Condition.g4).
The modifier registry is
[SigmaModifierFacade](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/rules/modifiers/SigmaModifierFacade.java).

## Every registered modifier

`SigmaDetectionItem.applyModifiers` applies modifiers in declaration order.
`SigmaModifier.typeCheck` and `apply`, plus `SigmaValueModifier` and
`SigmaListModifier`, check value versus list types and flatten expansions.
Every row needs a positive, negative, ordering, and wrong-type fixture.

| Operation ID | Registry name and source class | Transformation and preconditions |
| --- | --- | --- |
| SA-01.contains | `contains`: `SigmaContainsModifier.modify` | Add leading/trailing wildcards when absent. For regex, add `.*` unless anchored with `^` or `$`; compile the result. Reject an empty string in `fromMapping`. |
| SA-01.startswith | `startswith`: `SigmaStartswithModifier.modify` | Add trailing wildcard or unanchored regex `.*`; reject an empty string. |
| SA-01.endswith | `endswith`: `SigmaEndswithModifier.modify` | Add leading wildcard or unanchored regex `.*`; reject an empty string. |
| SA-01.base64 | `base64`: `SigmaBase64Modifier.modify` | Base64-encode source string bytes. Reject wildcard/special string fragments. Record the charset assumption. |
| SA-01.base64offset | `base64offset`: `SigmaBase64OffsetModifier.modify` | Encode three alignment variants. Prefix zero/one/two spaces; use source start offsets `[0,2,3]` and end offsets `[0,-3,-2]`. Return an expansion. Reject wildcard/special fragments. |
| SA-01.wide | `wide`: `SigmaWideModifier.modify` | Convert plain fragments through UTF-16LE bytes and UTF-8 string construction; retain wildcard/placeholder fragments. Qualify byte behavior with ASCII and non-ASCII fixtures. |
| SA-01.windash | `windash`: `SigmaWindowsDashModifier.modify` | Replace argument-prefix `-`/`/` matches with both alternatives through `_windash` placeholders. Preserve `_ws_` handling and expansion order. |
| SA-01.regex | `re`: `SigmaRegularExpressionModifier.modify`; `SigmaRegularExpression.compile`, `escape` | Apply only to an unmodified string. Replace spaces with `_ws_`; Java `Pattern` validates syntax, then OpenSearch evaluates the rendered regex. Both dialects need reference fixtures. |
| SA-01.cidr | `cidr`: `SigmaCIDRModifier.modify`; `SigmaCIDRExpression` | Apply only to an unmodified string. Source validation accepts IPv4 and optional prefix 0..32. No IPv6 or arbitrary Sigma CIDR claim follows. |
| SA-01.all | `all`: `SigmaAllModifier.modify` | Change the detection item's value linking from OR to AND. Preserve duplicates and empty-list behavior. |
| SA-01.lt | `lt`: `SigmaLessThanModifier` and `SigmaCompareModifier.modify` | Wrap a numeric value in strict less-than comparison. |
| SA-01.lte | `lte`: `SigmaLessThanEqualModifier` and `SigmaCompareModifier.modify` | Wrap a numeric value in inclusive less-than comparison. |
| SA-01.gt | `gt`: `SigmaGreaterThanModifier` and `SigmaCompareModifier.modify` | Wrap a numeric value in strict greater-than comparison. |
| SA-01.gte | `gte`: `SigmaGreaterThanEqualModifier` and `SigmaCompareModifier.modify` | Wrap a numeric value in inclusive greater-than comparison. |

Unknown modifier names fail at `fromMapping`. This list does not include
Sigma features that the pinned registry does not implement. Modifier chains
are separate variants in the rule metadata report.

## Every aggregate and threshold variant

The source grammar
[Aggregation.g4](../../../../../security-analytics/src/main/grammars/Aggregation.g4)
admits `count`, `sum`, `min`, `max`, and `avg`. The
[builder seam](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/rules/backend/AggregationBuilders.java)
also supports `terms` and `median_absolute_deviation`. Those two are required
delegated builder variants; the grammar does not establish YAML reachability.

| Operation ID | Source symbols and variant | Required calculation |
| --- | --- | --- |
| SA-02.parse | `SigmaCondition` constructor; `AggregationTraverseVisitor.visitComparisonExpressionWithOperator`, `visitAggExpressionParens`, `visitNumericConst`, `visitNumericVariable`, `visitGroupby_expr`; `AggregationItem` | Split at exact ` | ` separator. Extract aggregate function/field, optional group field, threshold, comparison, and rule timeframe. Preserve decimal threshold and field name. |
| SA-02.count-documents | `OSQueryBackend.convertAggregation`: `count(*)` | Count documents per terms group, or per `_index` when no group is supplied. Use bucket `_count`, not value count. |
| SA-02.count-values | `AggregationBuilders.getAggregationBuilderByFunction`: `count` | OpenSearch `value_count(field)`: count values, including multivalue contributions. This is not SQL `COUNT(*)` or distinct count. |
| SA-02.average | Builder `avg` | Average numeric field values with the source missing/multivalue semantics and precision. |
| SA-02.minimum | Builder `min` | Minimum numeric field value; qualify empty and missing groups. |
| SA-02.maximum | Builder `max` | Maximum numeric field value; qualify empty and missing groups. |
| SA-02.sum | Builder `sum` | Sum numeric field values; qualify overflow, reduction order, empty groups, and precision. |
| SA-02.terms | Builder `terms`; outer `TermsAggregationBuilder("result_agg")` | Group by mapped field or `_index`. Qualify multivalue membership, null/missing values, default bucket limits, ordering, and ties. Report omitted buckets instead of a clean complete result. |
| SA-02.mad | Builder `median_absolute_deviation` | MAD numeric reduction. Source delegates approximation and configuration to OpenSearch. Record the reference artifact, permitted error, and empty/multivalue behavior. |
| SA-02.threshold | `OSQueryBackend.convertAggregation`; Alerting `BucketSelectorExtAggregationBuilder` | Every `>`, `>=`, `<`, `<=`, and `==` threshold variant, including zero, negative, fractional, and boundary values. Preserve group/member evidence. |
| SA-02.window | `QueryBackend.convertRule`; `TransportIndexDetectorAction.createBucketLevelMonitorRequest` | Timestamp range is `(period_end - timeframe, period_end]`, default `1h`, when the timestamp alias exists. Source omits this range when the alias is absent. Local packages must expose that coverage condition. |
| SA-02.finding-members | `createDocLevelMonitorMatchAllRequest`; `WorkflowService.createWorkflowRequest`; Alerting chained monitor | Matching buckets -> related documents and rule-tagged findings through the final chained document monitor. Retain member identities and rule/aggregate revision. |

## Source defects and reference cases

These cases require explicit difference records and fixtures before 7.5.9 can
claim parity or correction:

- `SigmaTypeFacade` maps object classes other than Boolean, Integer, Float,
  and String to null. SnakeYAML can supply Double or Long. Do not silently
  discard their values in the local typed contract.
- `SigmaNumber.equals` compares the numeric variant, not the numeric value.
  Inspect callers and test equal/different values before porting that helper.
- `QueryBackend.decideConvertConditionAsInExpression` has a short-circuit
  condition that prevents its intended same-field optimization. Preserve
  results, not an unused optimization.
- Java regex validation and OpenSearch/Lucene regex execution use different
  syntax and behavior. A Java parse pass is insufficient execution proof.
- `SigmaWideModifier` uses UTF-16LE-to-UTF-8 string construction. Do not assume
  it implements every Sigma wide-string interpretation.
- Aggregate builder defaults can omit terms buckets. Query display limits,
  search hit limits, and those defaults cannot silently truncate internal
  analysis input.
- Timestamp alias absence removes the upstream aggregate time filter. Report
  missing timestamp mapping or record an explicitly tested alternative.

## Reference tests and closure

Source tests are under
[`src/test/java/org/opensearch/securityanalytics`](../../../../../security-analytics/src/test/java/org/opensearch/securityanalytics/).
Use `rules/objects/SigmaRuleTests`, `SigmaDetectionTests`,
`SigmaDetectionItemTests`, `SigmaDetectionsTests`, `SigmaLogSourceTests`,
`SigmaRuleTagTests`; `rules/condition/ConditionTests`;
`rules/backend/QueryBackendTests`; `rules/aggregation/AggregationBackendTests`;
all `rules/modifiers/*Tests`; `rules/types/*Tests`; `mapper/MapperUtilsTests`,
`MapperServiceTests`, `MapperRestApiIT`; `LogTypeServiceTests`;
`resthandler/RuleRestApiIT`, `OCSFDetectorRestApiIT`, and
`action/ValidateRulesRequestTests`/`ValidateRulesResponseTests`.

The pinned tests are reference material, not proof of a local port. Required
local fixtures include missing/null/multivalue fields; keyword and mapped-field
matching; escaped wildcard and reserved tokens; case/analyzer behavior; each
modifier and chain; all comparisons and aggregates; exact timestamp boundaries;
changed mappings/rules; empty replacements; checkpoint replay; and incomplete
input. Corpus parse alone cannot close these operations.
