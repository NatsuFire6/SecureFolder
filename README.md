# SecureFolder

SecureFolder is a Windows launcher for VeraCrypt file containers with the `.sf`
extension. A mounted container appears as a drive letter in File Explorer; it
is not a native Windows directory while locked.

## Requirements

- Windows
- VeraCrypt installed from its official distribution (SecureFolder offers to
  download and install the pinned 64-bit VeraCrypt 1.26.29 MSI when needed)
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
3. Return to SecureFolder and choose **Ouvrir un coffre .sf**. VeraCrypt prompts
   for the password on its secure desktop and mounts the container as a drive.
4. Choose **Paramètres** to authenticate again and configure the timeout,
   sleep/shutdown locking, and whether a blocked dismount may be forced.
5. Choose **Associer les fichiers .sf** and, if Windows asks, select
   SecureFolder under **Default apps**.

SecureFolder does not save or pass the password to another process. VeraCrypt
handles password entry, volume creation, encryption, mounting, and dismounting.
Lock preferences are stored in the hidden `.securefolder-settings.ini` file
inside the mounted encrypted volume, never alongside the `.sf` container.

The timeout is measured from when the volume is mounted. At timeout,
SecureFolder warns you to save and close documents, dismounts the volume, and
asks VeraCrypt to mount it again. A correct password keeps the volume open;
canceling or entering a wrong password leaves it locked. If open files prevent
normal dismount, SecureFolder warns and refuses to claim the volume is locked.
If forced dismount is enabled, a separate confirmation warns that unsaved
changes can be lost.

Windows does not let SecureFolder force another application to save or discard
its documents, block window switching globally, or guarantee that an app has no
unsaved in-memory changes. Close/save files before reauthentication. When the
container is locked, VeraCrypt's dismounted volume rejects filesystem access;
applications may still retain their own unsaved in-memory document buffers.

The encrypted container protects its contents while stored on disk. While
unlocked, Windows and applications can access plaintext; operating-system
memory, paging, crash-dump, and hibernation behavior is outside SecureFolder's
control. Automatic locking also depends on SecureFolder remaining operational.
