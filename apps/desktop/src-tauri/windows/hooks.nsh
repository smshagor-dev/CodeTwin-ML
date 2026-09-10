!macro NSIS_HOOK_POSTINSTALL
  MessageBox MB_YESNO|MB_ICONINFORMATION \
    "CodeTwin ML installs the OpenMindAI Dataset package during setup.$\r$\n$\r$\nTwo CodeXGLUE datasets use the C-UDA and are limited to computational use. Upstream attribution and redistribution terms remain applicable. SWE-bench tasks can contain third-party repository material under upstream terms.$\r$\n$\r$\nC-UDA terms: https://spdx.org/licenses/C-UDA-1.0.html$\r$\n$\r$\nSelect Yes to accept the dataset terms and download all four OpenMindAI Dataset packages. Selecting No cancels setup." \
    IDYES codetwin_dataset_terms_accepted
  Abort

codetwin_dataset_terms_accepted:
codetwin_dataset_retry:
  DetailPrint "Downloading and verifying OpenMindAI Dataset packages..."
  nsExec::ExecToLog 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\install-openmindai-datasets.ps1" -InstallRoot "$LOCALAPPDATA\CodeTwinML\datasets" -ReleaseTag "openmindai-datasets-v1.0.0" -AcceptDatasetTerms'
  Pop $R0
  StrCmp $R0 "0" codetwin_dataset_complete

  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION \
    "OpenMindAI Dataset download or integrity verification failed. CodeTwin ML requires the complete dataset package for this installation profile.$\r$\n$\r$\nCheck your internet connection and choose Retry. Choose Cancel to stop setup." \
    IDRETRY codetwin_dataset_retry
  Abort

codetwin_dataset_complete:
  DetailPrint "OpenMindAI Dataset installation verified."
!macroend
