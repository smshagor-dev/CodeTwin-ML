# Dataset attribution and terms

CodeTwin ML does not claim ownership of these upstream datasets. The catalog pins source repositories and revisions so every cached copy remains traceable.

| Dataset | Hugging Face repository | Pinned revision | Catalog license |
| --- | --- | --- | --- |
| CodeXGLUE Defect Detection / Devign | `google/code_x_glue_cc_defect_detection` | `69bd48c03223c2104342acd9a807caf61ac3efb8` | C-UDA |
| CodeXGLUE Code Refinement | `google/code_x_glue_cc_code_refinement` | `07ab797a018d0d5c448b56eb26b5e11aa5ad7659` | C-UDA |
| SWE-bench Verified | `princeton-nlp/SWE-bench_Verified` | `c104f840cc67f8b6eec6f759ebc8b2693d585d4a` | upstream dataset license not declared in catalog source |
| Code Security Vulnerability Dataset | `ayshajavd/code-security-vulnerability-dataset` | data revision `074abd8` | Apache-2.0 |

The two CodeXGLUE datasets require explicit C-UDA acceptance before download. Users remain responsible for applicable attribution, computational-use, and redistribution obligations. C-UDA text: https://spdx.org/licenses/C-UDA-1.0.html

The catalog intentionally does not invent a license for SWE-bench Verified. Review https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified before accepting `upstream-unspecified`.

The Code Security Vulnerability Dataset card declares Apache-2.0. Source: https://huggingface.co/datasets/ayshajavd/code-security-vulnerability-dataset . License: https://www.apache.org/licenses/LICENSE-2.0

After prefetch, `_codetwin_source.json` records upstream repository, revision, license metadata, byte counts, and SHA-256 values for the cached files. Preserve this provenance when datasets are used for training or evaluation.
