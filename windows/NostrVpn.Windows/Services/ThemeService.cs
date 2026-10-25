using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace NostrVpn.Windows.Services;

public sealed class ThemeService : IDisposable
{
    public const string System = "system";
    public const string Light = "light";
    public const string Dark = "dark";

    private const string AppKeyPath = @"Software\Nostr VPN";
    private const string ThemeValueName = "Theme";
    private const string PersonalizeKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private const string AppsUseLightThemeName = "AppsUseLightTheme";

    private readonly Dispatcher _dispatcher;
    private string _preference;
    private string _appliedTheme = "";
    private bool _disposed;

    /// Raised after the theme dictionary was swapped so listeners can
    /// refresh resources that are not reachable through DynamicResource.
    public event Action? Applied;

    public ThemeService()
    {
        _dispatcher = Application.Current.Dispatcher;
        _preference = LoadPreference();
        ApplyTheme(Resolve(_preference));
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
    }

    public string Preference => _preference;

    public static Brush Brush(string key) => (Brush)Application.Current.Resources[key];

    public void SetPreference(string theme)
    {
        if (_preference == theme)
        {
            return;
        }
        _preference = theme;
        using var key = Registry.CurrentUser.CreateSubKey(AppKeyPath);
        key?.SetValue(ThemeValueName, theme);
        ApplyTheme(Resolve(_preference));
    }

    public void Dispose()
    {
        _disposed = true;
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
    }

    private void OnUserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        if (_disposed || _preference != System || e.Category != UserPreferenceCategory.General)
        {
            return;
        }
        ApplyTheme(Resolve(_preference));
    }

    private static string Resolve(string preference)
    {
        if (preference == Light || preference == Dark)
        {
            return preference;
        }
        using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKeyPath);
        return key?.GetValue(AppsUseLightThemeName) is int value && value == 0 ? Dark : Light;
    }

    private void ApplyTheme(string theme)
    {
        if (theme == _appliedTheme)
        {
            return;
        }
        _appliedTheme = theme;
        _dispatcher.Invoke(() =>
            Application.Current.Resources.MergedDictionaries[0] =
                new ResourceDictionary { Source = new Uri($"Themes/{theme}.xaml", UriKind.Relative) });
        Applied?.Invoke();
    }

    private static string LoadPreference()
    {
        using var key = Registry.CurrentUser.OpenSubKey(AppKeyPath);
        var stored = key?.GetValue(ThemeValueName) as string;
        return stored is Light or Dark or System ? stored : System;
    }
}
