# CT Report Summary

- reports: 16
- selected SECURE: 11
- selected INSECURE: 4
- selected UNKNOWN: 1
- avg binsec calls: 166.56

## Top 15 by BINSEC Calls

| benchmark | suite | baseline | selected | binsec_calls | stop_reason | policy_kind |
|---|---|---|---|---:|---|---|
| candidate_7_insecure | Examples-CT/ct-shift-window/1_insecure | INSECURE | INSECURE | 437 | max_clauses | DNF |
| candidate_6_insecure | Examples-CT/ct-or-multi-branch/1_insecure | INSECURE | SECURE | 388 | saturated | CLAUSE |
| candidate_8_insecure | Examples-CT/ct-and-window/1_insecure | INSECURE | INSECURE | 387 | max_clauses | DNF |
| bench_ct_select_naive | Benchmarks/ct-select | INSECURE | SECURE | 356 | - | CLAUSE |
| candidate_5_insecure | Examples-CT/ct-easy-pass/1_insecure | INSECURE | INSECURE | 325 | max_clauses | DNF |
| bench_ct_sort_multiplex | Benchmarks/ct-sort | INSECURE | SECURE | 209 | - | CLAUSE |
| bench_ct_sort_negative | Benchmarks/ct-sort | INSECURE | SECURE | 209 | - | CLAUSE |
| bench_ct_sort | Benchmarks/ct-sort | INSECURE | UNKNOWN | 183 | saturated | UNSAT |
| candidate_4_insecure | Examples-CT/ct-asym-policy/1_insecure | INSECURE | SECURE | 62 | saturated | DNF |
| candidate_3_insecure | Examples-CT/ct-range-policy/1_insecure | INSECURE | SECURE | 62 | saturated | DNF |
| candidate_1_insecure | Examples-CT/simple-ct-branch/1_insecure | INSECURE | INSECURE | 32 | saturated | DNF |
| bench_ct_select_v1 | Benchmarks/ct-select | SECURE | SECURE | 3 | - | TRUE |
| bench_ct_select_v2 | Benchmarks/ct-select | SECURE | SECURE | 3 | - | TRUE |
| bench_ct_select_v3 | Benchmarks/ct-select | SECURE | SECURE | 3 | - | TRUE |
| bench_ct_select_v4 | Benchmarks/ct-select | SECURE | SECURE | 3 | - | TRUE |
