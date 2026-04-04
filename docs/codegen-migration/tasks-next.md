# Next Tasks

This is the immediate execution queue following the planning/documentation phase.

## Now

- [ ] N1. Confirm and snapshot representative legacy resolved XML fixtures from `common`, `foundation`, and `main`
- [ ] N2. Produce generated-output inventory for final emitted files
- [ ] N3. Choose the first representative entity path to reverse-engineer end-to-end

## Recommended first representative paths

### Small / foundational
- [ ] N4. `common/module_assert`
- [ ] N5. `common/module_buffer`

### Richer / cross-project semantics
- [ ] N6. `foundation/module_message_info`
- [ ] N7. `foundation/c_module_vscf_message_info`

### Wrapper-oriented
- [ ] N8. `foundation/go_project_foundation`

## Parser/resolver preparation

- [ ] N9. Define source-model types for `main.xml`, project XML, wrapper XML, and entity XML
- [ ] N10. Define typed IR IDs for project/module/class/interface/enum/wrapper nodes
- [ ] N11. Document a first-pass resolution pipeline in terms of parse -> index -> resolve -> emit

## Explicitly deferred

- [ ] N12. Do not use Python wrapper-resolved XML as the first parity oracle
- [ ] N13. Do not design the new runtime around emitting resolved XML
