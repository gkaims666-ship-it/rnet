package com.rnet.app.diag

import android.content.Context
import android.os.Build
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * CrashHandler — captures uncaught exceptions to a local, sanitized crash log.
 *
 * Privacy (consistent with the app's zero-retention design):
 *   A report contains ONLY a timestamp, the app version, the Android API level,
 *   the crashing thread name, and the exception stack trace. It does NOT contain
 *   the device model/manufacturer, any account identifier, or the destinations
 *   you connected to. As a belt-and-suspenders step, any IPv4 address or
 *   host:port token that happens to surface in an exception message is redacted
 *   before the report is written to disk.
 *
 * Storage:
 *   Reports are written to the app's own external files dir
 *   (Android/data/<pkg>/files/crash-logs/). They NEVER leave the device on
 *   their own — there is no automatic upload and no embedded credential of any
 *   kind. The user explicitly shares them from the app when they choose to.
 */
object CrashHandler {

    private const val DIR = "crash-logs"
    private const val MAX_REPORTS = 20
    private const val MAX_SHARE_BYTES = 128 * 1024

    @Volatile private var installed = false
    @Volatile private var appVersion = "unknown"

    /** Install the global uncaught-exception handler. Safe to call once at startup. */
    fun install(context: Context, versionName: String) {
        if (installed) return
        installed = true
        appVersion = versionName
        val appCtx = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            runCatching { write(appCtx, thread, throwable, kind = "FATAL") }
            // Chain to the platform handler so the OS still reports/terminates as usual.
            previous?.uncaughtException(thread, throwable)
        }
    }

    /**
     * Record a non-fatal background failure (e.g. a coroutine that would
     * otherwise crash the process) without terminating the app. The report is
     * written to the same crash-logs dir so the user can still share it.
     */
    fun record(context: Context, label: String, throwable: Throwable) {
        runCatching {
            write(context.applicationContext, Thread.currentThread(), throwable, kind = "NON-FATAL:$label")
        }
    }

    private fun dir(context: Context): File? {
        val base = context.getExternalFilesDir(null) ?: context.filesDir ?: return null
        val d = File(base, DIR)
        if (!d.exists()) d.mkdirs()
        return d
    }

    private fun write(context: Context, thread: Thread, t: Throwable, kind: String) {
        val d = dir(context) ?: return
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.US).format(Date())
        val sw = StringWriter()
        t.printStackTrace(PrintWriter(sw))
        val report = buildString {
            append("=== RNET crash report ===\n")
            append("kind:    ").append(kind).append('\n')
            append("time:    ").append(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())).append('\n')
            append("version: ").append(appVersion).append('\n')
            append("api:     ").append(Build.VERSION.SDK_INT).append('\n')
            append("thread:  ").append(thread.name).append('\n')
            append("---- stack trace ----\n")
            append(sw.toString())
        }
        runCatching { File(d, "crash-$stamp.txt").writeText(sanitize(report)) }
        prune(d)
    }

    /** Redact IPv4 addresses and host:port tokens that might appear in messages. */
    private fun sanitize(s: String): String {
        var out = s.replace(Regex("""\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"""), "[ip]")
        out = out.replace(Regex("""\[ip]:\d{1,5}"""), "[ip]:[port]")
        return out
    }

    private fun prune(d: File) {
        val files = d.listFiles()
            ?.filter { it.name.startsWith("crash-") }
            ?.sortedByDescending { it.lastModified() } ?: return
        files.drop(MAX_REPORTS).forEach { runCatching { it.delete() } }
    }

    fun hasReports(context: Context): Boolean =
        dir(context)?.listFiles()?.any { it.name.startsWith("crash-") } == true

    /**
     * Concatenated recent reports, newest first, bounded in size. Null if none.
     * Used by the UI's "Share crash logs" action.
     */
    fun recentReportsText(context: Context): String? {
        val files = dir(context)?.listFiles()
            ?.filter { it.name.startsWith("crash-") }
            ?.sortedByDescending { it.lastModified() } ?: return null
        if (files.isEmpty()) return null
        val sb = StringBuilder()
        for (f in files) {
            val chunk = runCatching { f.readText() }.getOrNull() ?: continue
            if (sb.length + chunk.length > MAX_SHARE_BYTES) break
            sb.append(chunk).append("\n\n")
        }
        return sb.toString().ifEmpty { null }
    }

    fun clear(context: Context) {
        dir(context)?.listFiles()?.forEach { runCatching { it.delete() } }
    }
}
