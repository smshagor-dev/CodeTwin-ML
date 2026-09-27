!macro NSIS_HOOK_POSTINSTALL
  ; Silent installs are used by clean-machine release smoke tests and enterprise
  ; deployment. They must never prompt for or implicitly accept optional
  ; third-party dataset terms.
  IfSilent codetwin_dataset_skipped 0

  MessageBox MB_YESNO|MB_ICONINFORMATION \
    "CodeTwin ML can install the optional OpenMindAI Dataset package during setup.$\r$\n$\r$\nTwo CodeXGLUE datasets use the C-UDA and are limited to computational use. Upstream attribution and redistribution terms remain applicable. SWE-bench tasks can contain third-party repository material under upstream terms.$\r$\n$\r$\nC-UDA terms: https://spdx.org/licenses/C-UDA-1.0.html$\r$\n$\r$\nSelect Yes to accept the dataset terms and download all four OpenMindAI Dataset packages. Select No to finish installing CodeTwin ML without datasets; dataset-backed ML features will remain unavailable until the package is installed later." \
    IDYES codetwin_dataset_terms_accepted \
    IDNO codetwin_dataset_skipped

codetwin_dataset_terms_accepted:
codetwin_dataset_retry:
  DetailPrint "Downloading and verifying OpenMindAI Dataset packages..."
  nsExec::ExecToLog 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\install-openmindai-datasets.ps1" -InstallRoot "$LOCALAPPDATA\CodeTwinML\datasets" -ReleaseTag "openmindai-datasets-v1.0.0" -AcceptDatasetTerms'
  Pop $R0
  StrCmp $R0 "0" codetwin_dataset_complete

  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION \
    "OpenMindAI Dataset download or integrity verification failed.$\r$\n$\r$\nChoose Retry to try again. Choose Cancel to finish installing the base CodeTwin ML application without datasets. Dataset-backed ML features will remain unavailable until a verified dataset package is installed." \
    IDRETRY codetwin_dataset_retry \
    IDCANCEL codetwin_dataset_skipped

codetwin_dataset_skipped:
  DetailPrint "OpenMindAI Dataset installation skipped; base CodeTwin ML installation will continue."
  Goto codetwin_dataset_done

codetwin_dataset_complete:
  DetailPrint "OpenMindAI Dataset installation verified."

codetwin_dataset_done:
!macroend
