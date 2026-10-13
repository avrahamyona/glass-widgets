; electron-builder NSIS include (picked up automatically from build/installer.nsh).
; 0.4.64 renamed the shortcuts to the Hebrew name (nsis.shortcutName). An update/install over an
; older version would otherwise leave the OLD "GlassWidgets" shortcuts next to the new ones.
; customInstall runs after the new shortcuts are created. Only the exact old file names, only in
; the current user's Desktop and Start Menu, and only if they exist. Nothing else is touched.
!macro customInstall
  IfFileExists "$DESKTOP\GlassWidgets.lnk" 0 +2
    Delete "$DESKTOP\GlassWidgets.lnk"
  IfFileExists "$SMPROGRAMS\GlassWidgets.lnk" 0 +2
    Delete "$SMPROGRAMS\GlassWidgets.lnk"
!macroend
