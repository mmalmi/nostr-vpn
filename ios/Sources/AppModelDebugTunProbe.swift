import Darwin
import Foundation

private struct DebugUdpEchoResult: Sendable {
    let sentPackets: Int
    let replyPackets: Int
    let errors: [String]
}

extension AppModel {
    func runDebugTunPacketProbe(arguments: [String]) async -> [String: Any] {
        let requestedTarget = Self.argumentValue(
            after: "--nvpn-debug-tun-probe-target",
            in: arguments
        )?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let target: String
        if let requestedTarget, !requestedTarget.isEmpty {
            target = requestedTarget
        } else {
            target = "10.44.255.254"
        }
        let port = Self.argumentValue(after: "--nvpn-debug-tun-probe-port", in: arguments)
            .flatMap(UInt16.init) ?? 9
        let packetCount = Self.clampedIntArgument(
            "--nvpn-debug-tun-probe-count",
            in: arguments,
            defaultValue: 4,
            minValue: 1,
            maxValue: 256
        )
        let waitSeconds = Self.clampedDoubleArgument(
            "--nvpn-debug-tun-probe-wait-seconds",
            in: arguments,
            defaultValue: 6.0,
            minValue: 0.5,
            maxValue: 60.0
        )
        let pollIntervalNanoseconds: UInt64 = 100_000_000
        var result: [String: Any] = [
            "tunPacketProbeTarget": target,
            "tunPacketProbePort": Int(port),
            "tunPacketProbeExpectedPackets": packetCount,
            "tunPacketProbePollIntervalMs": Int(pollIntervalNanoseconds / 1_000_000),
            "tunPacketProbeReadIncreased": false,
        ]

        let baselineRuntimeJson = await vpnController.runtimeStateJson()
        guard let baselineRead = Self.runtimeCounter(
            "tunPacketsRead",
            from: baselineRuntimeJson
        ),
            let baselineBytesRead = Self.runtimeCounter(
                "tunBytesRead",
                from: baselineRuntimeJson
            ),
            let baselineWritten = Self.runtimeCounter(
                "tunPacketsWritten",
                from: baselineRuntimeJson
            ),
            let baselineBytesWritten = Self.runtimeCounter(
                "tunBytesWritten",
                from: baselineRuntimeJson
            ),
            let baselineDropped = Self.runtimeCounter(
                "tunPacketsDropped",
                from: baselineRuntimeJson
            )
        else {
            result["tunPacketProbeError"] = "baseline TUN counters missing"
            return result
        }
        result["tunPacketProbeBaselineRead"] = Self.jsonCounterValue(baselineRead)
        result["tunPacketProbeBaselineBytesRead"] = Self.jsonCounterValue(baselineBytesRead)
        result["tunPacketProbeBaselineWritten"] = Self.jsonCounterValue(baselineWritten)
        result["tunPacketProbeBaselineBytesWritten"] = Self.jsonCounterValue(baselineBytesWritten)
        result["tunPacketProbeBaselineDropped"] = Self.jsonCounterValue(baselineDropped)

        let probeStartedAt = Date()
        let echoTask = Task.detached(priority: .utility) {
            Self.sendAndReceiveDebugUdpEchoes(
                target: target,
                port: port,
                packetCount: packetCount,
                waitSeconds: waitSeconds
            )
        }
        let deadline = probeStartedAt.addingTimeInterval(waitSeconds)
        var finalRead = baselineRead
        var finalBytesRead = baselineBytesRead
        var finalWritten = baselineWritten
        var finalBytesWritten = baselineBytesWritten
        var finalDropped = baselineDropped
        var pollCount = 0
        var firstObservedAt: Date?
        while Date() < deadline {
            pollCount += 1
            let runtimeJson = await vpnController.runtimeStateJson()
            if let currentRead = Self.runtimeCounter(
                "tunPacketsRead",
                from: runtimeJson
            ),
                let currentBytesRead = Self.runtimeCounter(
                    "tunBytesRead",
                    from: runtimeJson
                ),
                let currentWritten = Self.runtimeCounter(
                    "tunPacketsWritten",
                    from: runtimeJson
                ),
                let currentBytesWritten = Self.runtimeCounter(
                    "tunBytesWritten",
                    from: runtimeJson
                ),
                let currentDropped = Self.runtimeCounter(
                    "tunPacketsDropped",
                    from: runtimeJson
                )
            {
                finalRead = currentRead
                finalBytesRead = currentBytesRead
                finalWritten = currentWritten
                finalBytesWritten = currentBytesWritten
                finalDropped = currentDropped
                if currentRead > baselineRead && firstObservedAt == nil {
                    firstObservedAt = Date()
                }
            }
            try? await Task.sleep(nanoseconds: pollIntervalNanoseconds)
        }

        let echoResult = await echoTask.value
        let sentPackets = echoResult.sentPackets
        result["tunPacketProbeSentPackets"] = sentPackets
        result["tunPacketProbeReplyPackets"] = echoResult.replyPackets
        result["tunPacketProbeMissingReplyPackets"] = max(
            0,
            packetCount - echoResult.replyPackets
        )
        let requiredRead = Self.saturatingAdd(baselineRead, UInt64(sentPackets))
        result["tunPacketProbeRequiredRead"] = Self.jsonCounterValue(requiredRead)
        if !echoResult.errors.isEmpty {
            result["tunPacketProbeReplyError"] = echoResult.errors.joined(separator: "; ")
        }
        guard sentPackets > 0 else {
            result["tunPacketProbeError"] = "no UDP probe packets sent"
            return result
        }

        Self.finishTunPacketProbeResult(
            &result,
            sentPackets: sentPackets,
            baselineRead: baselineRead,
            baselineBytesRead: baselineBytesRead,
            baselineWritten: baselineWritten,
            baselineBytesWritten: baselineBytesWritten,
            baselineDropped: baselineDropped,
            finalRead: finalRead,
            finalBytesRead: finalBytesRead,
            finalWritten: finalWritten,
            finalBytesWritten: finalBytesWritten,
            finalDropped: finalDropped,
            probeStartedAt: probeStartedAt,
            firstObservedAt: firstObservedAt,
            pollCount: pollCount
        )
        result["tunPacketProbeReadIncreased"] = finalRead >= requiredRead
        return result
    }

    nonisolated private static func finishTunPacketProbeResult(
        _ result: inout [String: Any],
        sentPackets: Int,
        baselineRead: UInt64,
        baselineBytesRead: UInt64,
        baselineWritten: UInt64,
        baselineBytesWritten: UInt64,
        baselineDropped: UInt64,
        finalRead: UInt64,
        finalBytesRead: UInt64,
        finalWritten: UInt64,
        finalBytesWritten: UInt64,
        finalDropped: UInt64,
        probeStartedAt: Date,
        firstObservedAt: Date?,
        pollCount: Int
    ) {
        let observedPackets = saturatingSubtract(finalRead, baselineRead)
        let observedBytes = saturatingSubtract(finalBytesRead, baselineBytesRead)
        let observedWritten = saturatingSubtract(finalWritten, baselineWritten)
        let observedBytesWritten = saturatingSubtract(finalBytesWritten, baselineBytesWritten)
        let droppedDelta = saturatingSubtract(finalDropped, baselineDropped)
        let missingPackets = saturatingSubtract(UInt64(sentPackets), observedPackets)
        result["tunPacketProbeFinalRead"] = jsonCounterValue(finalRead)
        result["tunPacketProbeObservedPackets"] = jsonCounterValue(observedPackets)
        result["tunPacketProbeMissingPackets"] = jsonCounterValue(missingPackets)
        result["tunPacketProbeFinalBytesRead"] = jsonCounterValue(finalBytesRead)
        result["tunPacketProbeObservedBytesRead"] = jsonCounterValue(observedBytes)
        result["tunPacketProbeBytesReadIncreased"] = observedBytes > 0
        result["tunPacketProbeFinalWritten"] = jsonCounterValue(finalWritten)
        result["tunPacketProbeObservedWritten"] = jsonCounterValue(observedWritten)
        result["tunPacketProbeFinalBytesWritten"] = jsonCounterValue(finalBytesWritten)
        result["tunPacketProbeObservedBytesWritten"] = jsonCounterValue(observedBytesWritten)
        result["tunPacketProbeWrittenIncreased"] = observedWritten > 0
        result["tunPacketProbeBytesWrittenIncreased"] = observedBytesWritten > 0
        result["tunPacketProbeFinalDropped"] = jsonCounterValue(finalDropped)
        result["tunPacketProbeDroppedDelta"] = jsonCounterValue(droppedDelta)
        result["tunPacketProbeDroppedIncreased"] = droppedDelta > 0
        result["tunPacketProbeElapsedMs"] = Int(Date().timeIntervalSince(probeStartedAt) * 1000)
        result["tunPacketProbePolls"] = pollCount
        if let firstObservedAt {
            result["tunPacketProbeFirstObservedMs"] = Int(
                firstObservedAt.timeIntervalSince(probeStartedAt) * 1000
            )
        }
    }

    nonisolated private static func sendAndReceiveDebugUdpEchoes(
        target: String,
        port: UInt16,
        packetCount: Int,
        waitSeconds: Double
    ) -> DebugUdpEchoResult {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else {
            return DebugUdpEchoResult(
                sentPackets: 0,
                replyPackets: 0,
                errors: ["socket: \(String(cString: strerror(errno)))"]
            )
        }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, target, &addr.sin_addr) == 1 else {
            return DebugUdpEchoResult(
                sentPackets: 0,
                replyPackets: 0,
                errors: ["invalid IPv4 target"]
            )
        }

        var receiveTimeout = timeval(tv_sec: 0, tv_usec: 200_000)
        let timeoutStatus = withUnsafePointer(to: &receiveTimeout) { pointer in
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
        guard timeoutStatus == 0 else {
            return DebugUdpEchoResult(
                sentPackets: 0,
                replyPackets: 0,
                errors: ["SO_RCVTIMEO: \(String(cString: strerror(errno)))"]
            )
        }

        let nonce = UInt64(Date().timeIntervalSince1970 * 1_000_000)
        let payloads = (0..<packetCount).map { sequence in
            Data("nvpn-ios-probe-\(nonce)-\(sequence)".utf8)
        }
        var expectedReplies = Set<Data>()
        var errors: [String] = []
        for payload in payloads {
            let sent = payload.withUnsafeBytes { bytes in
                withUnsafePointer(to: &addr) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockAddr in
                        sendto(
                            fd,
                            bytes.baseAddress,
                            bytes.count,
                            0,
                            sockAddr,
                            socklen_t(MemoryLayout<sockaddr_in>.size)
                        )
                    }
                }
            }
            if sent == payload.count {
                expectedReplies.insert(payload)
            } else if sent < 0 {
                errors.append("sendto: \(String(cString: strerror(errno)))")
            } else {
                errors.append("sendto wrote \(sent)/\(payload.count) bytes")
            }
        }
        guard !expectedReplies.isEmpty else {
            return DebugUdpEchoResult(
                sentPackets: 0,
                replyPackets: 0,
                errors: errors
            )
        }

        let deadline = Date().addingTimeInterval(waitSeconds)
        var receivedReplies = Set<Data>()
        var buffer = [UInt8](repeating: 0, count: 2_048)
        while receivedReplies.count < expectedReplies.count, Date() < deadline {
            let received = buffer.withUnsafeMutableBytes { bytes in
                recv(fd, bytes.baseAddress, bytes.count, 0)
            }
            if received > 0 {
                let payload = Data(buffer.prefix(received))
                if expectedReplies.contains(payload) {
                    receivedReplies.insert(payload)
                } else {
                    errors.append("received unexpected UDP payload")
                }
                continue
            }
            if received < 0,
               errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
            {
                continue
            }
            if received < 0 {
                errors.append("recv: \(String(cString: strerror(errno)))")
            } else {
                errors.append("received empty UDP payload")
            }
            break
        }
        if receivedReplies.count != expectedReplies.count {
            errors.append(
                "received \(receivedReplies.count)/\(expectedReplies.count) UDP echo replies"
            )
        }
        return DebugUdpEchoResult(
            sentPackets: expectedReplies.count,
            replyPackets: receivedReplies.count,
            errors: errors
        )
    }

    nonisolated private static func saturatingAdd(_ left: UInt64, _ right: UInt64) -> UInt64 {
        let (value, overflow) = left.addingReportingOverflow(right)
        return overflow ? UInt64.max : value
    }

    nonisolated private static func saturatingSubtract(_ left: UInt64, _ right: UInt64) -> UInt64 {
        left >= right ? left - right : 0
    }

    nonisolated private static func runtimeCounter(_ key: String, from json: String?) -> UInt64? {
        guard let json,
              let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let value = object[key]
        else {
            return nil
        }
        if let number = value as? NSNumber {
            return number.uint64Value
        }
        if let string = value as? String {
            return UInt64(string)
        }
        return nil
    }

    nonisolated private static func jsonCounterValue(_ value: UInt64) -> Any {
        if value <= UInt64(Int.max) {
            return Int(value)
        }
        return String(value)
    }
}
