using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using NostrVpn.Windows.Controls;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.ViewModels;

internal static class Program
{
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private const string Participant = "participant";
    private static int _passed;

    [STAThread]
    private static void Main(string[] args)
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
        Console.WriteLine($"WINDOWS_JOIN_NAVIGATION_OK: {_passed} cases");

        UpdateSteps(args.Length > 0 ? args[0] : null);
        Console.WriteLine($"WINDOWS_UPDATE_STEPS_OK: {_passed} cases");
    }

    /// The banner renders each install step the core reports: progress while
    /// busy, then a plain failure with Retry and a fallback, or the result.
    private static void UpdateSteps(string? shots)
    {
        var app = new NostrVpn.Windows.App();
        app.InitializeComponent();
        var model = Create(accepted: false);
        Set(model, "_updateAvailable", true);
        Set(model, "_updateVersion", "v4.1.22");
        Set(model, "_updateStatus", "");
        var dir = Path.Combine(Path.GetTempPath(), $"nvpn-update-steps-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var config = Path.Combine(dir, "config.toml");
        var marker = Path.Combine(dir, "update-pending.json");
        try
        {
            Show(model, AppCoreClient.DesktopUpdate("view", "4.1.19", config));
            Require(!model.UpdateView.Active && model.UpdatePrimaryVisible && model.UpdatePrimaryLabel == "Install"
                && model.UpdateAutoInstallVisible && model.UpdateStripeText.StartsWith("Update available: v4.1.22"),
                "an available update offers Install");
            Render(model, shots, "01-available");
            Pass("update available");

            // Views the core produced during a live install of v4.1.22.
            Show(model, Captured("""{"step":"fetching","active":true,"busy":true,"title":"Finding the update…","progress":null}"""));
            Require(model.UpdateStripeText == "Finding the update…" && model.UpdateProgressVisible
                && model.UpdateProgressIndeterminate && !model.UpdatePrimaryVisible && !model.UpdateAutoInstallVisible,
                "finding shows an indeterminate bar and no Install button");
            Render(model, shots, "02-finding");
            Show(model, Captured("""{"step":"downloading","active":true,"busy":true,"title":"Downloading v4.1.22… 55%","detail":"38 MB of 69 MB","progress":0.5462487078253117}"""));
            Require(model.UpdateStripeText == "Downloading v4.1.22… 55%" && !model.UpdateProgressIndeterminate
                && Math.Abs(model.UpdateProgressPercent - 54.62) < 0.01 && model.UpdateDetail == "38 MB of 69 MB",
                "downloading shows the percentage and a determinate bar");
            Render(model, shots, "03-downloading");
            Show(model, Captured("""{"step":"verifying","active":true,"busy":true,"title":"Checking the download…","progress":1.0}"""));
            Require(model.UpdateStripeText == "Checking the download…" && model.UpdateProgressPercent == 100, "verifying");
            Render(model, shots, "04-verifying");
            Pass("install progress steps");

            File.WriteAllText(marker, """{"version":"v4.1.22"}""");
            Show(model, AppCoreClient.DesktopUpdate("resume", "4.1.19", config));
            Require(model.UpdateFailed && model.UpdateBannerVisible && !model.UpdateProgressVisible
                && model.UpdateStripeText == "The update to v4.1.22 didn't finish."
                && model.UpdatePrimaryVisible && model.UpdatePrimaryLabel == "Retry"
                && model.UpdateSecondaryVisible && model.UpdateSecondaryLabel == "Download page",
                "an unfinished install says so and offers Retry and the download page");
            Require(model.UpdateSettingsText == "The update to v4.1.22 didn't finish.", "Settings repeats the failure");
            Render(model, shots, "05-did-not-finish");
            Pass("failure with Retry");

            Set(model, "_updateAvailable", false);
            File.WriteAllText(marker, """{"version":"v4.1.22"}""");
            Show(model, AppCoreClient.DesktopUpdate("resume", "4.1.22", config));
            Require(model.UpdateBannerVisible && model.UpdateStripeText == "Updated to v4.1.22"
                && !model.UpdatePrimaryVisible && !File.Exists(marker), "a finished install reports the new version once");
            Render(model, shots, "06-updated");
            Pass("update result after restart");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static DesktopUpdateView Captured(string json) =>
        JsonSerializer.Deserialize<DesktopUpdateView>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

    private static void Show(AppViewModel model, DesktopUpdateView view) =>
        typeof(AppViewModel).GetProperty(nameof(AppViewModel.UpdateView))!.GetSetMethod(nonPublic: true)!.Invoke(model, [view]);

    private static void Render(AppViewModel model, string? shots, string name)
    {
        if (shots is null)
        {
            return;
        }
        var banner = new UpdateBanner { DataContext = model, Width = 920 };
        banner.Measure(new Size(920, double.PositiveInfinity));
        banner.Arrange(new Rect(new Size(920, banner.DesiredSize.Height)));
        banner.UpdateLayout();
        var bitmap = new RenderTargetBitmap(920, Math.Max(1, (int)Math.Ceiling(banner.ActualHeight)), 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(banner);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        Directory.CreateDirectory(shots);
        using var file = File.Create(Path.Combine(shots, $"{name}.png"));
        encoder.Save(file);
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
