using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows.Threading;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.ViewModels;

internal static class Program
{
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private const string Participant = "participant";
    private static int _passed;

    [STAThread]
    private static void Main()
    {
        var pending = Create(accepted: false);
        Complete(pending);
        Require(pending.Page == AppPage.Devices, "pending submission must reveal the roster");
        Require(pending.ParticipantInput == "" && pending.ParticipantAliasInput == "", "submitted draft clears");
        Require(pending.Notice == "", "pending participant must not claim acceptance");
        Require(pending.ActiveNetwork!.Participants[0].AcceptedRosterAutomationId == "", "pending row is not accepted");
        typeof(AppViewModel).GetProperty(nameof(AppViewModel.State))!
            .GetSetMethod(nonPublic: true)!.Invoke(pending, [State(accepted: true)]);
        Require(pending.Page == AppPage.Devices, "later snapshot keeps the roster visible");
        Require(pending.ActiveNetwork!.Participants[0].AcceptedRosterAutomationId == $"RosterParticipantAccepted-{Participant}",
            "later snapshot exposes the exact accepted row");
        Pass("pending submission then accepted snapshot");

        var immediate = Create(accepted: true);
        Complete(immediate);
        Require(immediate.Page == AppPage.Devices && immediate.Notice == "Device added", "immediate acceptance");
        Pass("immediate acceptance");

        var failed = Create(accepted: false);
        Complete(failed, added: false);
        Require(failed.Page == AppPage.AddDevice && failed.ParticipantInput == Participant
            && failed.ParticipantAliasInput == "alias" && failed.Notice == "", "failed submission preserves form");
        var timer = (DispatcherTimer)typeof(AppViewModel).GetField("_refreshTimer", Private)!.GetValue(failed)!;
        Require(timer.Interval == TimeSpan.FromSeconds(15), "failed submission does not start coordination refresh");
        Pass("failed submission");

        Preserve("navigation during dispatch", model => model.Page = AppPage.Settings);
        Preserve("network selection during dispatch", model => Set(model, "_shownNetworkId", "other-network"));
        Preserve("participant edit during dispatch", model => model.ParticipantInput = "different-participant");
        Preserve("alias edit during dispatch", model => model.ParticipantAliasInput = "different-alias");

        var cold = (AppViewModel)RuntimeHelpers.GetUninitializedObject(typeof(AppViewModel));
        Set(cold, "_state", new NativeAppState());
        Set(cold, "_refreshTimer", new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) });
        Require(cold.VpnStatusText == "Off", "default state renders Off before the core answers");
        Require(cold.HeroSubtitle == "0 of 0 connected", "default state renders empty peer counts");
        Pass("default state renders before core init");

        var preCore = Create(accepted: false);
        typeof(AppViewModel).GetMethod("ApplyState", Private)!
            .Invoke(preCore, [State(accepted: false), true]);
        Require(preCore.State.Networks.Count == 2, "state applies while the core is still initializing");
        Require(preCore.JoinRequestQr.Width == 0 && preCore.JoinRequestQr.Error == "",
            "missing core skips QR decoding instead of throwing");
        Pass("state applies before core init");
        Console.WriteLine($"WINDOWS_JOIN_NAVIGATION_OK: {_passed} cases");
    }

    private static NativeAppState State(bool accepted)
    {
        var state = new NativeAppState();
        var network = new NativeNetworkState { Id = "network", Enabled = true, LocalIsAdmin = true };
        network.Participants.Add(new NativeParticipantState { Npub = Participant, RosterAccepted = accepted });
        state.Networks.Add(network);
        state.Networks.Add(new NativeNetworkState { Id = "other-network", LocalIsAdmin = true });
        return state;
    }

    private static AppViewModel Create(bool accepted)
    {
        // Exercise the real view model without starting its native core, timers,
        // update checks, or user startup-registration side effects.
        var model = (AppViewModel)RuntimeHelpers.GetUninitializedObject(typeof(AppViewModel));
        Set(model, "_refreshTimer", new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) });
        Set(model, "_state", State(accepted));
        Set(model, "_page", AppPage.AddDevice);
        Set(model, "_shownNetworkId", "network");
        Set(model, "_participantInput", Participant);
        Set(model, "_participantAliasInput", "alias");
        Set(model, "_notice", "");
        return model;
    }

    private static void Complete(AppViewModel model, bool added = true) => typeof(AppViewModel)
        .GetMethod("CompleteParticipantSubmission", Private)!.Invoke(model, [added, "network", Participant, "alias"]);

    private static void Preserve(string label, Action<AppViewModel> change)
    {
        var model = Create(accepted: true);
        change(model);
        var before = (model.Page, model.ActiveNetwork!.Id, model.ParticipantInput, model.ParticipantAliasInput, model.Notice);
        Complete(model);
        Require(before == (model.Page, model.ActiveNetwork!.Id, model.ParticipantInput, model.ParticipantAliasInput, model.Notice), label);
        Pass(label);
    }

    private static void Set(AppViewModel model, string field, object value) =>
        typeof(AppViewModel).GetField(field, Private)!.SetValue(model, value);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void Pass(string label)
    {
        _passed++;
        Console.WriteLine($"PASS: {label}");
    }
}
