using System.Text;

namespace VpnClient.Ui;

public static class WindowsCommandLine
{
    // Windows CommandLineToArgvW / CRT escaping, including backslashes before quotes/end.
    public static string Quote(string argument)
    {
        var result = new StringBuilder("\"");
        var slashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\') { slashes++; continue; }
            result.Append('\\', character == '"' ? slashes * 2 + 1 : slashes);
            result.Append(character);
            slashes = 0;
        }
        result.Append('\\', slashes * 2);
        return result.Append('"').ToString();
    }
}
