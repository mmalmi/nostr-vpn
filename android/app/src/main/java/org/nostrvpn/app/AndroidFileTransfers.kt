package org.nostrvpn.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.currentCoroutineContext
import android.webkit.MimeTypeMap
import org.nostrvpn.app.core.TransferFileState
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import java.io.File
import java.util.UUID

private data class SharedFileInfo(val uri: Uri, val name: String, val size: Long)

private fun sharedFileInfo(context: Context, uri: Uri): SharedFileInfo {
    require(uri.scheme == "content") { "Choose a file from the file picker." }
    return context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) SharedFileInfo(uri, cursor.getString(0) ?: "File", if (cursor.isNull(1)) 0 else cursor.getLong(1).coerceAtLeast(0)) else null
    } ?: SharedFileInfo(uri, "File", 0)
}

private suspend fun stageSharedFiles(context: Context, uris: List<Uri>, progress: (String) -> Unit): List<String> {
    require(uris.isNotEmpty() && uris.size <= 32) { "Choose between 1 and 32 files." }
    val batches = mutableListOf<File>()
    try {
        return withContext(Dispatchers.IO) {
            val files = uris.map { sharedFileInfo(context, it) }
            val total = files.sumOf { it.size }
            var copied = 0L
            var lastUpdate = 0L
            files.map { file ->
                currentCoroutineContext().ensureActive()
                val batch = appCoreDataDir(context).resolve("file-transfer-outbox").resolve(UUID.randomUUID().toString())
                check(batch.mkdirs()) { "Could not prepare files." }
                batches.add(batch)
                val name = file.name
                require(name.isNotBlank() && name != "." && name != ".." && name.toByteArray(Charsets.UTF_8).size <= 240 && name.none { it in "/\\<>:\"|?*" || it.isISOControl() }) { "Invalid file name." }
                val target = batch.resolve(name)
                check(target.createNewFile()) { "Could not prepare $name." }
                context.contentResolver.openInputStream(file.uri)?.use { input ->
                    target.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var fileBytes = 0L
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val count = input.read(buffer)
                            if (count < 0) break
                            fileBytes += count
                            require(fileBytes <= 100L * 1024 * 1024 * 1024) { "Choose files smaller than 100 GB." }
                            output.write(buffer, 0, count)
                            copied += count
                            val now = android.os.SystemClock.elapsedRealtime()
                            if (now - lastUpdate >= 150) {
                                val detail = "Preparing $name · ${formatBytes(copied)}" + if (total > 0) " of ${formatBytes(total)}" else ""
                                withContext(Dispatchers.Main) { progress(detail) }
                                lastUpdate = now
                            }
                        }
                    }
                } ?: error("Could not read $name.")
                target.absolutePath
            }
        }
    } catch (error: Exception) {
        withContext(NonCancellable + Dispatchers.IO) { batches.forEach { it.deleteRecursively() } }
        throw error
    }
}

private fun sendFilesAction(npub: String, paths: List<String>) =
    JSONObject().put("type", "send_files").put("npub", npub).put("paths", JSONArray(paths))

@Composable
internal fun SendFilesButton(npub: String, enabled: Boolean, dispatch: (JSONObject) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var selectedNpub by remember { mutableStateOf(npub) }
    var preparation by remember { mutableStateOf<Job?>(null) }
    var progress by remember { mutableStateOf("") }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) preparation = scope.launch {
            busy = true; error = ""; progress = "Preparing files…"
            try { dispatch(sendFilesAction(selectedNpub, stageSharedFiles(context, uris) { progress = it })) }
            catch (_: CancellationException) { error = "File preparation cancelled." }
            catch (failure: Exception) { error = failure.message ?: "Could not prepare files." }
            finally { busy = false }
        }
    }
    OutlinedButton(onClick = { selectedNpub = npub; picker.launch(arrayOf("*/*")) }, enabled = enabled && !busy) {
        Text(if (busy) "Preparing files…" else "Send files")
    }
    if (busy) {
        Text(progress, style = MaterialTheme.typography.bodySmall)
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        TextButton(onClick = { preparation?.cancel() }) { Text("Cancel") }
    }
    if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
}

@Composable
internal fun FileTransfersCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    var openError by remember { mutableStateOf("") }
    AppCard {
        Text("Files", style = MaterialTheme.typography.titleMedium)
        FileNotificationPermission()
        if (state.fileTransfers.isEmpty()) Text("Received files will appear here.", style = MaterialTheme.typography.bodySmall)
        if (!state.vpnActive && state.fileTransfers.any { it.status in listOf("queued", "offered", "preparing", "connecting", "transferring", "paused") }) Text("Connect VPN to continue transfers.", style = MaterialTheme.typography.bodySmall)
        if (openError.isNotEmpty()) Text(openError, color = MaterialTheme.colorScheme.error)
        Column(Modifier.heightIn(max = 300.dp).verticalScroll(rememberScrollState())) {
        state.fileTransfers.forEach { transfer ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                if (transfer.status == "unavailable") {
                    Text("Files unavailable", style = MaterialTheme.typography.titleSmall)
                } else {
                Text(transfer.files.firstOrNull()?.name.orEmpty() + if (transfer.files.size > 1) " + ${transfer.files.size - 1} files" else "")
                Text("${if (transfer.isSender) "To" else "From"} ${transfer.peerName.ifBlank { transfer.peerNpub.take(10) + "…" + transfer.peerNpub.takeLast(6) }}", style = MaterialTheme.typography.bodySmall)
                if (transfer.status in listOf("preparing", "connecting", "transferring", "paused")) {
                    LinearProgressIndicator(progress = { (transfer.transferredBytes.toDouble() / transfer.totalBytes.coerceAtLeast(1)).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                }
                Text(when (transfer.status) {
                    "queued" -> "Waiting to send"
                    "cancelling" -> "Cancelling…"
                    "declining" -> "Declining…"
                    "offered" -> if (transfer.isSender) "Waiting for acceptance" else "Wants to send you files"
                    "preparing" -> "Preparing files…"
                    "connecting" -> "Connecting…"
                    "transferring" -> if (transfer.isSender) "Sending" else "Receiving"
                    "paused" -> "Paused"
                    "completed" -> if (transfer.isSender) "Sent" else "Received"
                    "failed" -> "Could not transfer files"
                    else -> transfer.status.replaceFirstChar { it.uppercase() }
                })
                Text("${formatBytes(transfer.transferredBytes)} / ${formatBytes(transfer.totalBytes)}", style = MaterialTheme.typography.bodySmall)
                }
                transfer.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                fun act(action: String) { dispatch(JSONObject().put("type", "${action}_file_transfer").put("id", transfer.id)) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (transfer.status == "offered" && !transfer.isSender) {
                        Button(enabled = state.vpnActive, onClick = { act("accept") }) { Text("Accept") }
                        TextButton(onClick = { act("decline") }) { Text("Decline") }
                    } else if (transfer.status in listOf("queued", "offered", "preparing", "connecting", "transferring", "paused")) {
                        if (transfer.status == "paused") TextButton(enabled = state.vpnActive, onClick = { act("resume") }) { Text("Resume") }
                        TextButton(onClick = { act("cancel") }) { Text("Cancel") }
                    }
                }
                if (transfer.status == "completed" && !transfer.isSender) transfer.files.forEach { file ->
                    if (file.localPath != null) ReceivedFileActions(file) { openError = it }
                }
            }
            HorizontalDivider()
        }
        }
    }
}

@Composable
private fun FileNotificationPermission() {
    val context = LocalContext.current
    var allowed by remember { mutableStateOf(context.getSystemService(android.app.NotificationManager::class.java).areNotificationsEnabled()) }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed = it; AndroidFileNotifications.refreshActive() }
    val settings = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        allowed = context.getSystemService(android.app.NotificationManager::class.java).areNotificationsEnabled()
        AndroidFileNotifications.refreshActive()
    }
    if (!allowed) TextButton(onClick = {
        if (android.os.Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            permission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        else settings.launch(Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, context.packageName))
    }) { Text("Enable file notifications") }
}

@Suppress("DEPRECATION")
internal fun sharedFileUris(intent: Intent?): List<Uri> = when (intent?.action) {
    Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
    Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.toList().orEmpty()
    else -> emptyList()
}.filter { it.scheme == "content" }

@Composable
private fun ReceivedFileActions(file: TransferFileState, onError: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(file.name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"
    var saving by remember { mutableStateOf(false) }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(mime)) { destination ->
        if (destination != null) scope.launch {
            saving = true
            try {
                withContext(Dispatchers.IO) {
                    File(requireNotNull(file.localPath)).inputStream().use { input ->
                        context.contentResolver.openOutputStream(destination)?.use { output -> input.copyTo(output, 64 * 1024) }
                            ?: error("Could not save ${file.name}.")
                    }
                }
            } catch (error: Exception) { onError(error.message ?: "Could not save file.") }
            finally { saving = false }
        }
    }
    fun open(share: Boolean) {
        runCatching {
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", File(requireNotNull(file.localPath)))
            val intent = if (share) Intent(Intent.ACTION_SEND).setType(mime).putExtra(Intent.EXTRA_STREAM, uri)
                else Intent(Intent.ACTION_VIEW).setDataAndType(uri, mime)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            context.startActivity(if (share) Intent.createChooser(intent, "Share ${file.name}") else intent)
        }.onFailure { onError(if (it is android.content.ActivityNotFoundException) "No app can open this file. Save or share it instead." else it.message ?: "Could not open file.") }
    }
    Text(file.name, style = MaterialTheme.typography.bodySmall)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(onClick = { open(false) }) { Text("Open") }
        TextButton(enabled = !saving, onClick = { save.launch(file.name) }) { Text(if (saving) "Saving…" else "Save") }
        TextButton(onClick = { open(true) }) { Text("Share") }
    }
}

@Composable
internal fun SharedFilesDialog(state: AppState, uris: List<Uri>, onDismiss: () -> Unit, connect: () -> Unit, dispatch: (JSONObject) -> Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var progress by remember { mutableStateOf("") }
    var preparation by remember { mutableStateOf<Job?>(null) }
    var selected by remember { mutableStateOf<String?>(null) }
    var requested by remember { mutableStateOf(false) }
    var summary by remember(uris) { mutableStateOf("${uris.size} ${if (uris.size == 1) "file" else "files"}") }
    LaunchedEffect(uris) {
        runCatching { withContext(Dispatchers.IO) { uris.map { sharedFileInfo(context, it) } } }.onSuccess { files ->
            summary = files.firstOrNull()?.name.orEmpty() + (if (files.size > 1) " + ${files.size - 1} files" else "") + " · ${formatBytes(files.sumOf { it.size })}"
        }
    }
    val peers = state.networks.filter { it.enabled }.flatMap { it.participants }
        .filter { it.npub != state.ownNpub && it.rosterAccepted }.distinctBy { it.npub }.sortedByDescending { it.reachable }
    val recipient = peers.firstOrNull { it.npub == selected }
    LaunchedEffect(requested, state.vpnActive, recipient?.reachable) {
        if (requested && !busy && state.vpnActive && recipient?.reachable == true) {
            preparation = scope.launch {
                busy = true; error = ""; progress = "Preparing files…"
                var paths = emptyList<String>()
                try {
                    paths = stageSharedFiles(context, uris) { progress = it }
                    if (dispatch(sendFilesAction(recipient.npub, paths))) { paths = emptyList(); onDismiss() }
                    else error = "Could not send files. Check the connection and try again."
                } catch (_: CancellationException) { error = "File preparation cancelled." }
                catch (failure: Exception) { error = failure.message ?: "Could not prepare files." }
                finally {
                    withContext(NonCancellable + Dispatchers.IO) { paths.forEach { File(it).parentFile?.deleteRecursively() } }
                    busy = false; requested = false
                }
            }
        }
    }
    fun dismiss() { preparation?.cancel(); onDismiss() }
    AlertDialog(onDismissRequest = { dismiss() }, title = { Text("Send files") }, text = {
        Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
            Text(summary)
            if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
            if (busy) { Text(progress); LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            else if (requested) {
                Text(state.error.ifBlank { "Waiting for the device… Keep this window open." })
                TextButton(onClick = { requested = false }) { Text("Choose another device") }
            }
            else if (peers.isEmpty()) Text("Add another device to your network to send files.")
            else if (!state.vpnActive) Text("Choose a device. Your files will stay here while VPN connects.")
            peers.forEach { peer ->
                TextButton(enabled = !busy && !requested, onClick = { selected = peer.npub }) {
                    Column {
                        Text((if (selected == peer.npub) "✓ " else "") + peer.alias.ifBlank { peer.magicDnsAlias.ifBlank { "Device" } })
                        Text("${peer.npub.take(10)}…${peer.npub.takeLast(6)} · ${if (peer.reachable) "Online" else "Offline"}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }, confirmButton = {
        TextButton(enabled = selected != null && !busy && !requested, onClick = { requested = true; if (!state.vpnActive) connect() }) {
            Text(if (state.vpnActive) "Send" else "Connect and send")
        }
    }, dismissButton = { TextButton(onClick = { dismiss() }) { Text("Cancel") } })
}
