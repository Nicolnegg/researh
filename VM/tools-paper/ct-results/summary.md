# CT Report Summary

- reports: 16
- selected SECURE: 8
- selected INSECURE: 5
- selected UNKNOWN: 3
- avg binsec calls: 157.56

## Top 15 by BINSEC Calls

| benchmark | suite | baseline | selected | binsec_calls | stop_reason | policy_kind |
|---|---|---|---|---:|---|---|
| candidate_7_insecure | Examples-CT/ct-shift-window/1_insecure | INSECURE | INSECURE | 437 | max_clauses | CLAUSE |
| candidate_6_insecure | Examples-CT/ct-or-multi-branch/1_insecure | INSECURE | SECURE | 388 | saturated | CLAUSE |
| candidate_8_insecure | Examples-CT/ct-and-window/1_insecure | INSECURE | INSECURE | 387 | max_clauses | CLAUSE |
| candidate_5_insecure | Examples-CT/ct-easy-pass/1_insecure | INSECURE | INSECURE | 325 | max_clauses | CLAUSE |
| bench_ct_select_naive | Benchmarks/ct-select | INSECURE | INSECURE | 259 | max_clauses | CLAUSE |
| bench_ct_sort | Benchmarks/ct-sort | INSECURE | UNKNOWN | 183 | saturated | CLAUSE |
| bench_ct_sort_multiplex | Benchmarks/ct-sort | INSECURE | UNKNOWN | 183 | saturated | CLAUSE |
| bench_ct_sort_negative | Benchmarks/ct-sort | INSECURE | UNKNOWN | 183 | saturated | CLAUSE |
| candidate_4_insecure | Examples-CT/ct-asym-policy/1_insecure | INSECURE | SECURE | 62 | saturated | DNF |
| candidate_3_insecure | Examples-CT/ct-range-policy/1_insecure | INSECURE | SECURE | 62 | saturated | DNF |
| candidate_1_insecure | Examples-CT/simple-ct-branch/1_insecure | INSECURE | INSECURE | 32 | saturated | CLAUSE |
| bench_ct_select_v1 | Benchmarks/ct-select | SECURE | SECURE | 4 | None | TRUE |
| bench_ct_select_v2 | Benchmarks/ct-select | SECURE | SECURE | 4 | None | TRUE |
| bench_ct_select_v3 | Benchmarks/ct-select | SECURE | SECURE | 4 | None | TRUE |
| bench_ct_select_v4 | Benchmarks/ct-select | SECURE | SECURE | 4 | None | TRUE |
