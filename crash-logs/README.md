# crash-logs

A home for crash reports from the RNET app, so they can be tracked and fixed.

## How a crash gets here

The app installs a global crash handler at startup. When it hits an uncaught
exception it writes a report to the phone's app-private storage:

```
Android/data/com.rnet.app.debug/files/crash-logs/crash-<timestamp>.txt
```

Nothing is uploaded automatically. To get a report off the phone, open the app
and tap the **bug icon** in the top bar — that opens the system share sheet, so
you can send the log to yourself (Telegram, email), save it to Downloads, or
paste it into this folder / a GitHub issue. You choose where each report goes.

## Why there is no automatic upload

Auto-pushing from the app to GitHub would require a GitHub token baked into the
APK. Anyone who installed the app could extract that token and gain write access
to this repository. So the app never carries a credential; the user shares logs
explicitly instead. This keeps repo access off every phone that runs the build.

## What a report contains (and does not)

A report has only:

- timestamp
- app version
- Android API level (e.g. `34`)
- the crashing thread's name
- the exception stack trace

It deliberately does **not** contain the device model/manufacturer, any account
identifier, or the destinations you connected to. As an extra guard, any IPv4
address or `host:port` token that happens to appear in an exception message is
redacted to `[ip]` / `[ip]:[port]` before the report is written.

## Adding a report

Drop the `.txt` file into this folder (drag-and-drop in the GitHub web UI works)
or open an issue and paste its contents. Name them `crash-<date>-<short-note>.txt`
if you want them easy to tell apart.
