; ═══════════════════════════════════════════════════════════════════════
; Elara Node Windows installer (NSIS).
;
; Per-user installer for Windows. Installs at
; $LOCALAPPDATA\Elara\Node — no admin rights required — with a Start Menu
; shortcut, an Uninstaller entry in Add/Remove Programs, and a data dir
; defaulted to $APPDATA\Elara\data.
;
; Build (on Windows runner with NSIS installed via choco install nsis):
;     makensis /DBIN_PATH=path\to\elara-node.exe ^
;              /DOUT_PATH=Elara_Node_Setup-x86_64.exe ^
;              packaging\windows\elara-node.nsi
;
; The /DBIN_PATH and /DOUT_PATH defines let the CI substitute the freshly
; built artifact without editing this file.
; ═══════════════════════════════════════════════════════════════════════

!ifndef BIN_PATH
    !define BIN_PATH "..\..\target\release\elara-node.exe"
!endif
!ifndef OUT_PATH
    !define OUT_PATH "Elara_Node_Setup-x86_64.exe"
!endif
!ifndef VERSION
    !define VERSION "0.2.0"
!endif

Name "Elara Node"
OutFile "${OUT_PATH}"
Unicode true
RequestExecutionLevel user
InstallDir "$LOCALAPPDATA\Elara\Node"
InstallDirRegKey HKCU "Software\Elara\Node" "InstallDir"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName"      "Elara Node"
VIAddVersionKey "CompanyName"      "Elara Protocol"
VIAddVersionKey "FileDescription"  "Elara Protocol DAM mesh node"
VIAddVersionKey "FileVersion"      "${VERSION}"
VIAddVersionKey "LegalCopyright"   "Elara Protocol"

!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON   "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Elara Node (required)" SecCore
    SectionIn RO
    SetOutPath "$INSTDIR"
    File /oname=elara-node.exe "${BIN_PATH}"

    ; Pre-create the data dir so first run does not race on directory
    ; creation under a sandboxed start.
    CreateDirectory "$APPDATA\Elara\data"

    ; Start Menu shortcut launches with --data-dir defaulted; the user does
    ; not need to think about paths.
    CreateDirectory "$SMPROGRAMS\Elara"
    CreateShortcut "$SMPROGRAMS\Elara\Elara Node.lnk" \
        "$INSTDIR\elara-node.exe" \
        '--data-dir "$APPDATA\Elara\data"' \
        "$INSTDIR\elara-node.exe" 0 SW_SHOWNORMAL \
        "" "Run an Elara Protocol DAM mesh node"

    ; Uninstaller + Add/Remove Programs registry.
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    WriteRegStr HKCU "Software\Elara\Node" "InstallDir" "$INSTDIR"
    WriteRegStr HKCU "Software\Elara\Node" "Version"    "${VERSION}"

    !define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ElaraNode"
    WriteRegStr   HKCU "${UNINST_KEY}" "DisplayName"     "Elara Node"
    WriteRegStr   HKCU "${UNINST_KEY}" "DisplayVersion"  "${VERSION}"
    WriteRegStr   HKCU "${UNINST_KEY}" "Publisher"       "Elara Protocol"
    WriteRegStr   HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr   HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr   HKCU "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\elara-node.exe"
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Desktop shortcut" SecDesktop
    CreateShortcut "$DESKTOP\Elara Node.lnk" \
        "$INSTDIR\elara-node.exe" \
        '--data-dir "$APPDATA\Elara\data"' \
        "$INSTDIR\elara-node.exe" 0 SW_SHOWNORMAL \
        "" "Run an Elara Protocol DAM mesh node"
SectionEnd

LangString DESC_SecCore    ${LANG_ENGLISH} "Installs the elara-node binary, Start Menu shortcut, and uninstaller."
LangString DESC_SecDesktop ${LANG_ENGLISH} "Add an Elara Node shortcut to your Desktop."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}    $(DESC_SecCore)
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} $(DESC_SecDesktop)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
    Delete "$INSTDIR\elara-node.exe"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir  "$INSTDIR"

    Delete "$SMPROGRAMS\Elara\Elara Node.lnk"
    RMDir  "$SMPROGRAMS\Elara"
    Delete "$DESKTOP\Elara Node.lnk"

    DeleteRegKey HKCU "Software\Elara\Node"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ElaraNode"

    ; Note: the data dir at %APPDATA%\Elara\data is intentionally NOT
    ; removed — it holds the user's identity, keys, and ledger; users would
    ; lose access to their beat balance if we silently nuked it. They can
    ; delete it manually if they want a fully clean uninstall.
SectionEnd
