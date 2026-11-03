package org.nostrvpn.app.core

data class TransferFileState(val name: String, val sizeBytes: Long, val localPath: String?)
data class FileTransferState(
    val id: String,
    val peerNpub: String,
    val peerName: String,
    val isSender: Boolean,
    val files: List<TransferFileState>,
    val status: String,
    val transferredBytes: Long,
    val totalBytes: Long,
    val error: String?,
)
