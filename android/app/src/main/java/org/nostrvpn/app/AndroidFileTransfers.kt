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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import java.io.File
import java.util.UUID

private suspend fun stageSharedFiles(context: Context, uris: List<Uri>): List<String> = withContext(Dispatchers.IO) {
    require(uris.isNotEmpty() && uris.size <= 32) { "Choose between 1 and 32 files." }
    val batches = mutableListOf<File>()
    try {
        uris.map { uri ->
            val batch = appCoreDataDir(context).resolve("file-transfer-outbox").resolve(UUID.randomUUID().toString())
            check(batch.mkdirs()) { "Could not prepare files." }
            batches.add(batch)
            require(uri.scheme == "content") { "Choose a file from the file picker." }
            val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: "File"
            require(name.isNotBlank() && name != "." && name != ".." && name.toByteArray(Charsets.UTF_8).size <= 240 && name.none { it in "/\\<>:\"|?*" || it.isISOControl() }) { "Invalid file name." }
            val target = batch.resolve(name)
            check(target.createNewFile()) { "Choose files with different names." }
            context.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= 100L * 1024 * 1024 * 1024) { "Choose files smaller than 100 GB." }
                        output.write(buffer, 0, count)
                    }
                }
            } ?: error("Could not read $name.")
            target.absolutePath
        }
    } catch (error: Exception) {
        batches.forEach { it.deleteRecursively() }
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
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) scope.launch {
            busy = true; error = ""
            try { dispatch(sendFilesAction(selectedNpub, stageSharedFiles(context, uris))) }
            catch (failure: Exception) { error = failure.message ?: "Could not prepare files." }
            finally { busy = false }
        }
    }
    OutlinedButton(onClick = { selectedNpub = npub; picker.launch(arrayOf("*/*")) }, enabled = enabled && !busy) {
        Text(if (busy) "Preparing files…" else "Send files")
    }
    if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
}

@Composable
internal fun FileTransfersCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    if (state.fileTransfers.isEmpty()) return
    val context = LocalContext.current
    var openError by remember { mutableStateOf("") }
    AppCard {
        Text("Files", style = MaterialTheme.typography.titleMedium)
        if (!state.vpnActive) Text("Connect VPN to continue transfers.", style = MaterialTheme.typography.bodySmall)
        if (openError.isNotEmpty()) Text(openError, color = MaterialTheme.colorScheme.error)
        Column(Modifier.heightIn(max = 300.dp).verticalScroll(rememberScrollState())) {
        state.fileTransfers.forEach { transfer ->
            Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                if (transfer.status == "unavailable") {
                    Text("Files unavailable", style = MaterialTheme.typography.titleSmall)
                } else {
                Text(transfer.files.joinToString { it.name })
                Text("${if (transfer.isSender) "To" else "From"} ${transfer.peerName.ifBlank { transfer.peerNpub }}", style = MaterialTheme.typography.bodySmall)
                if (transfer.status in listOf("connecting", "transferring")) {
                    LinearProgressIndicator(progress = { (transfer.transferredBytes.toDouble() / transfer.totalBytes.coerceAtLeast(1)).toFloat().coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                }
                Text(when (transfer.status) {
                    "offered" -> if (transfer.isSender) "Waiting for acceptance" else "Wants to send you files"
                    "preparing" -> "Preparing…"
                    else -> transfer.status.replaceFirstChar { it.uppercase() }
                })
                Text("${formatBytes(transfer.transferredBytes)} / ${formatBytes(transfer.totalBytes)}", style = MaterialTheme.typography.bodySmall)
                }
                transfer.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                fun act(action: String) { dispatch(JSONObject().put("type", "${action}_file_transfer").put("id", transfer.id)) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (transfer.status == "offered" && !transfer.isSender) {
                        Button(enabled = state.vpnActive, onClick = { act("accept") }) { Text("Accept") }
                        TextButton(enabled = state.vpnActive, onClick = { act("decline") }) { Text("Decline") }
                    } else if (transfer.status in listOf("offered", "preparing", "connecting", "transferring", "paused")) {
                        if (transfer.status == "paused") TextButton(enabled = state.vpnActive, onClick = { act("resume") }) { Text("Resume") }
                        TextButton(enabled = state.vpnActive, onClick = { act("cancel") }) { Text("Cancel") }
                    }
                }
                if (transfer.status == "completed" && !transfer.isSender) transfer.files.forEach { file ->
                    file.localPath?.let { path ->
                        TextButton(onClick = {
                            runCatching {
                                val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", File(path))
                                val intent = Intent(Intent.ACTION_SEND).setType("application/octet-stream")
                                    .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                context.startActivity(Intent.createChooser(intent, "Save or share ${file.name}"))
                            }.onFailure { openError = it.message ?: "Could not open file." }
                        }) { Text("Save or share ${file.name}") }
                    }
                }
            }
            HorizontalDivider()
        }
        }
    }
}

@Suppress("DEPRECATION")
internal fun sharedFileUris(intent: Intent?): List<Uri> = when (intent?.action) {
    Intent.ACTION_SEND -> listOfNotNull(intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM))
    Intent.ACTION_SEND_MULTIPLE -> intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.toList().orEmpty()
    else -> emptyList()
}.filter { it.scheme == "content" }

@Composable
internal fun SharedFilesDialog(state: AppState, uris: List<Uri>, onDismiss: () -> Unit, dispatch: (JSONObject) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    val peers = state.networks.filter { state.vpnActive && it.enabled }.flatMap { it.participants }
        .filter { it.npub != state.ownNpub && it.reachable && it.rosterAccepted }.distinctBy { it.npub }
    AlertDialog(onDismissRequest = { if (!busy) onDismiss() }, title = { Text("Send ${uris.size} files") }, text = {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
            if (busy) Text("Preparing files…")
            if (peers.isEmpty()) Text("Connect to a network with another online device.")
            peers.forEach { peer ->
                TextButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true; error = ""
                        try { dispatch(sendFilesAction(peer.npub, stageSharedFiles(context, uris))); onDismiss() }
                        catch (failure: Exception) { error = failure.message ?: "Could not prepare files." }
                        finally { busy = false }
                    }
                }) { Text(peer.alias.ifBlank { peer.magicDnsAlias.ifBlank { peer.npub } }) }
            }
        }
    }, confirmButton = {}, dismissButton = { TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancel") } })
}
