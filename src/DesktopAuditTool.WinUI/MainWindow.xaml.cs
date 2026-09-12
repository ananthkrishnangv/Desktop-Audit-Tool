using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using WinRT.Interop;

namespace DesktopAuditTool_WinUI;

/// <summary>
/// The application window with native Windows App SDK Mica backdrop,
/// integrated custom titlebar, explicit Win32 taskbar icon registration,
/// and default full-screen / maximized launch presentation.
/// </summary>
public sealed partial class MainWindow : Window
{
    private const uint WM_SETICON = 0x0080;
    private const int ICON_SMALL = 0;
    private const int ICON_BIG = 1;
    private const uint IMAGE_ICON = 1;
    private const uint LR_LOADFROMFILE = 0x0010;

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr LoadImage(IntPtr hinst, string lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    private const int SW_MAXIMIZE = 3;

    private bool _isFirstActivation = true;

    public MainWindow()
    {
        InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        // Always maximize the window into full screen mode on startup
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.Maximize();
        }

        // Guarantee maximized presentation on window activation
        this.Activated += MainWindow_Activated;

        var iconPath = System.IO.Path.Combine(System.AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (System.IO.File.Exists(iconPath))
        {
            // Set AppWindow icon for title bar
            AppWindow.SetIcon(iconPath);

            // Win32 HWND Icon for Windows Taskbar & Alt-Tab Switcher
            try
            {
                var hwnd = WindowNative.GetWindowHandle(this);
                if (hwnd != IntPtr.Zero)
                {
                    var hIconBig = LoadImage(IntPtr.Zero, iconPath, IMAGE_ICON, 48, 48, LR_LOADFROMFILE);
                    if (hIconBig != IntPtr.Zero)
                    {
                        SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_BIG, hIconBig);
                    }

                    var hIconSmall = LoadImage(IntPtr.Zero, iconPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
                    if (hIconSmall != IntPtr.Zero)
                    {
                        SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_SMALL, hIconSmall);
                    }
                }
            }
            catch
            {
                // Fallback handled by AppWindow.SetIcon
            }
        }

        // Keyboard handler for F11 FullScreen toggle
        if (Content is UIElement rootElement)
        {
            rootElement.KeyDown += (s, e) =>
            {
                if (e.Key == Windows.System.VirtualKey.F11)
                {
                    ToggleFullScreen();
                    e.Handled = true;
                }
            };
        }

        // Navigate the root frame to the main page on startup.
        RootFrame.Navigate(typeof(MainPage));
    }

    private void MainWindow_Activated(object sender, WindowActivatedEventArgs args)
    {
        if (_isFirstActivation)
        {
            _isFirstActivation = false;

            if (AppWindow.Presenter is OverlappedPresenter presenter)
            {
                presenter.Maximize();
            }

            try
            {
                var hwnd = WindowNative.GetWindowHandle(this);
                if (hwnd != IntPtr.Zero)
                {
                    ShowWindow(hwnd, SW_MAXIMIZE);
                }
            }
            catch
            {
            }
        }
    }

    /// <summary>
    /// Toggles between Maximized Full Screen and Immersive Borderless Full Screen.
    /// </summary>
    public void ToggleFullScreen()
    {
        if (AppWindow.Presenter.Kind == AppWindowPresenterKind.FullScreen)
        {
            AppWindow.SetPresenter(AppWindowPresenterKind.Overlapped);
            if (AppWindow.Presenter is OverlappedPresenter presenter)
            {
                presenter.Maximize();
            }
        }
        else
        {
            AppWindow.SetPresenter(AppWindowPresenterKind.FullScreen);
        }
    }
}
