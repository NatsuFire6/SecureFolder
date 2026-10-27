# SecureFolder

SecureFolder is a Windows launcher for VeraCrypt file containers with the `.sf`
extension. A mounted container appears as a drive letter in File Explorer; it
is not a native Windows directory while locked.

## Requirements

- Windows
- VeraCrypt installed from its official distribution (SecureFolder offers to
  download and install the pinned 64-bit VeraCrypt 1.26.29 MSI when needed)
- Internet access on the first CMake configure, to fetch the pinned
  [WindowsInfo](https://github.com/NatsuFire6/WindowsInfo) dependency
- CMake and a C++20 compiler

Build with:

```powershell
cmake -S . -B build
cmake --build build
```

## First use

1. Start SecureFolder and choose **Créer un coffre**.
   If VeraCrypt is missing, SecureFolder asks before downloading the official
   MSI, checks its SHA-256 digest, and starts the Windows installer. Internet
   access, UAC approval, and accepting VeraCrypt's installer license are
   required.
2. SecureFolder starts the VeraCrypt Volume Creation Wizard. Choose **Create an
   encrypted file container**, then **Standard VeraCrypt volume**. Choose the
   path yourself and make sure its filename ends in `.sf`; VeraCrypt requires
   this path to be entered in its own wizard. Set a size of at least 10 MB,
   leave the other options at their defaults, enter the password in VeraCrypt,
   and move the mouse on its random-data screen until its indicator is full.
3. Return to SecureFolder and choose **Ouvrir un coffre .sf**. If a `.sf` file
   was already selected or opened with SecureFolder, it mounts that file
   directly; otherwise, choose a file in the picker. VeraCrypt prompts for the
   password on its secure desktop and mounts the container as a drive. Use
   **Changer de coffre...** to select a different container before opening it.
4. Choose **Paramètres** to authenticate again and configure the timeout,
   sleep/shutdown locking, and whether a blocked dismount may be forced.
   The timeout is displayed in minutes; 0 disables automatic locking.
5. Choose **Associer .sf + clic droit** and, if Windows asks, select
   SecureFolder under **Default apps**. This also adds **Créer un coffre
   SecureFolder ici (.sf)** to the context menu when right-clicking a folder or
   its background in File Explorer. The VeraCrypt wizard opens with that folder
   as its starting directory; enter a filename ending in `.sf`.

SecureFolder does not save or pass the password to another process. VeraCrypt
handles password entry, volume creation, encryption, mounting, and dismounting.
Lock preferences are stored in the hidden `.securefolder-settings.ini` file
inside the mounted encrypted volume, never alongside the `.sf` container.

The timeout is measured from when the volume is mounted. At timeout, or when
you request password verification in **Paramètres**, SecureFolder uses
WindowsInfo to find visible application windows whose titles match files in
the mounted volume, offers to send Ctrl+S and request those windows to close,
then gives the applications 10 seconds to save and close. WindowsInfo cannot
confirm that Ctrl+S actually saved a document. Any matching application still
open after that grace period may be terminated, including its other open
documents, before SecureFolder dismounts the volume and asks VeraCrypt to mount
it again. A correct
password keeps the volume open; canceling or entering a wrong password leaves
it locked. If windows do not close or open files prevent normal dismount,
SecureFolder warns and refuses to claim the volume is locked. If forced
dismount is enabled, a separate confirmation warns that unsaved changes can be
lost.

WindowsInfo can only match visible windows by the file name shown in their
title; it cannot confirm the full path or verify that an external application
actually saved the document after Ctrl+S. Applications may show their own
confirmation dialogs, and SecureFolder aborts locking if the matching windows
do not close during a manual password verification. During automatic timeout
locking, processes with matching windows that remain open after the 10-second
grace period are terminated; this can lose unsaved changes and close other
documents in those applications. Files without extensions and windows that do not show
the file name may not be detected. When the container is locked, VeraCrypt's
dismounted volume rejects filesystem access; applications may still retain
their own unsaved in-memory document buffers.

The encrypted container protects its contents while stored on disk. While
unlocked, Windows and applications can access plaintext; operating-system
memory, paging, crash-dump, and hibernation behavior is outside SecureFolder's
control. Automatic locking also depends on SecureFolder remaining operational.
