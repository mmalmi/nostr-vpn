using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NostrVpn.Windows.Core;

namespace NostrVpn.Windows.ViewModels;

public sealed partial class AppViewModel
{
    public void HandleDeepLink(string url)
    {
        if (_core is null)
        {
            // The core is still initializing; replay the link once it exists.
            _pendingDeepLinks.Add(url);
            return;
        }
#if DEBUG
        DebugRosterE2eTrace($"received {url}");
#endif
        if (url.StartsWith("nvpn://join-request", StringComparison.OrdinalIgnoreCase))
        {
            _ = ConfirmAndImportJoinRequestAsync(url);
            return;
        }

#if DEBUG
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !uri.Host.Equals("debug", StringComparison.OrdinalIgnoreCase))
        {
            DebugRosterE2eTrace("debug URL parse failed");
            return;
        }
        var query = ParseDebugQuery(uri.Query);
        var requestedNetwork = QueryValue(query, "networkId", "network");
        var network = State.Networks.FirstOrDefault(candidate =>
            string.IsNullOrWhiteSpace(requestedNetwork)
            || candidate.Id == requestedNetwork
            || candidate.NetworkId == requestedNetwork);
        if (network is null)
        {
            DebugRosterE2eTrace($"network not found: {requestedNetwork}");
            return;
        }
        if (uri.AbsolutePath.Equals("/accept-join", StringComparison.OrdinalIgnoreCase))
        {
            var requester = QueryValue(query, "requesterNpub", "requester")
                ?? network.InboundJoinRequests.FirstOrDefault()?.RequesterNpub;
            if (!string.IsNullOrWhiteSpace(requester))
            {
                DebugRosterE2eTrace($"dispatching accept for {network.Id}");
                _ = DispatchAsync(NativeActions.AcceptJoinRequest(network.Id, requester), "Adding device");
            }
        }
#endif
    }

#if DEBUG
    private static void DebugRosterE2eTrace(string message)
    {
        var path = Environment.GetEnvironmentVariable("NVPN_ROSTER_E2E_TRACE_PATH");
        if (!string.IsNullOrWhiteSpace(path))
        {
            File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
        }
    }

    private static Dictionary<string, string> ParseDebugQuery(string raw)
    {
        return raw.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(
                pair => Uri.UnescapeDataString(pair[0].Replace('+', ' ')),
                pair => pair.Length > 1 ? Uri.UnescapeDataString(pair[1].Replace('+', ' ')) : "",
                StringComparer.OrdinalIgnoreCase);
    }

    private static string? QueryValue(IReadOnlyDictionary<string, string> query, params string[] names)
    {
        return names.Select(name => query.GetValueOrDefault(name))
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    }
#endif
}
