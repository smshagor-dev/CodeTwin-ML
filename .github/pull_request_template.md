## Summary

Describe the user-visible or engineering change and the trust boundary it affects.

## Scope

- [ ] The PR is focused and does not contain unrelated branch history.
- [ ] If this PR was stacked on another feature branch, its parent is already on `main` or this PR has been rebased/merged onto the latest `main` before final merge.
- [ ] I verified the intended files are actually present in the resulting `main...head` diff; a child PR being marked `merged` on a feature-branch base is not sufficient evidence.

## Validation

Record the validation that actually executed. Do not mark a check as passed when a runner was never allocated.

- [ ] Rust format/clippy/tests executed successfully where applicable.
- [ ] Windows QA checks executed successfully where applicable.
- [ ] Python tests/compile checks executed successfully where applicable.
- [ ] Frontend typecheck/tests/build executed successfully where applicable.
- [ ] GitHub Actions jobs used real runners and contain executed steps/logs; `runner_id=0` / `steps=[]` is not a pass.

## Evidence truth

- [ ] Missing or failed evidence is not represented as zero/success.
- [ ] ML observations are not promoted to deterministic findings without deterministic evidence.
- [ ] QA plans/containment scaffolding are not described as executed test results.
- [ ] Applied repairs are not described as verified until fresh index/analyzer evidence confirms the post-state.

## Security and privacy

- [ ] No credentials, signing keys, private certificates, proprietary source, restricted model weights, or sensitive logs are committed.
- [ ] New filesystem/process/network behavior preserves the documented trust boundaries or updates the threat model with the new boundary.
- [ ] Integrity-sensitive artifacts use reviewable provenance and size/hash validation where appropriate.

## Release impact

- [ ] Documentation/capability status is updated when behavior changed.
- [ ] Migration, installer, dataset, or dependency-resolution changes are called out explicitly.
- [ ] Reproducibility claims rely on real package-manager-generated lock/provenance data, not fabricated metadata.
