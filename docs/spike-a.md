# Spike A: Glaze Behaviour for Duplicate Keys
Goal: Asessing how glaze handles duplicate keys (silently accepts or rejects outright). The results determine the design of the manifest parser and if a manual duplicate scanner is necessary.

## Testing Format
Testing is done by parsing various test json strings with different configurations and into different target structs. The baseline json string used is `{"a":1,"a":2}` mapped to the struct `struct TestStructA { int a }` tested on different configurations of `error_on_missing_keys` and `error_on_unknown_keys`. The full test suite is available at `tests/spikes/glaze_spikes.cpp`.

## Results
|json|struct|additional config|behaviour|
|----|------|-----------------|---------|
|`{"a":1,"a":2}`|`struct TestStructA { int a }`||last definition of a wins|
|`{"a":2,"a":1}`|`struct TestStructA { int a }`||last definition of a wins|
|`{"a":2,"a":2,"b":3}`|`struct TestStructA { int a }`||throws error on unknown key|
|`{"a":2,"a":2,"b":3}`|`struct TestStructA { int a }`|`error_on_unknown_keys = false`|b is silently dropped|
|`{"a":2,"a":null}`|`struct TestStructA { int a }`||throws parse error|
|`{"a":2,"a":null}`|`struct TestStructB { std::optional<int> a }`||written as `std::nullopt`|
|`{"a":2,"a":false}`|`struct TestStructA { int a }`||throws parse error|
|`{"a":2,"a":"string"}`|`struct TestStructA { int a }`||throws parse error|
|`{}`|`struct TestStructA { int a }`||a is filled with default value 0|
|`{}`|`struct TestStructA { int a }`|`error_on_missing_keys = true`|throws missing key error|
|`{}`|`struct TestStructB { std::optional<int> a }`||a is filled with default value of `std::nullopt`|
|`{"a":1,"a":2}`|`struct TestStructC { float a }`||int value written to float field|
|`{"a":1.0,"a":2.0}`|`struct TestStructA { int a }`||throws parse error|

## Findings
- Last definition of a duplicate key wins
- Unknown keys throw errors by default instead of being discarded
- `std::optional` can be used to map null
- Type coercion is not enforced if an implicit conversion is not available
- Missing keys are mapped to their default struct values unless configured to throw

## Conclusion
Glaze does not report duplicates and when one is found the last definition is used. A duplicate scanner is required to ensure that the manifest parser remains consistent.
