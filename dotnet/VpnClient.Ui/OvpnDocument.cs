using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace VpnClient.Ui;

public enum OvpnNodeKind { Trivia, Directive, InlineBlock, ConnectionStart, ConnectionEnd }

public sealed record OvpnNode(OvpnNodeKind Kind, string RawText, IReadOnlyList<string> Tokens,
    string SourcePath, int LineNumber)
{
    public string Name
    {
        get
        {
            if (Tokens.Count == 0) return "";
            var name = Tokens[0];
            if (name.Length >= 3 && name.StartsWith("--", StringComparison.Ordinal)) name = name[2..];
            if (Kind is OvpnNodeKind.InlineBlock or OvpnNodeKind.ConnectionStart or OvpnNodeKind.ConnectionEnd)
                name = name.Trim('<', '>', '/');
            return name.ToLowerInvariant();
        }
    }

    public OvpnNode WithTokens(IEnumerable<string> tokens)
    {
        var values = tokens.ToArray();
        return this with { Kind = OvpnNodeKind.Directive, Tokens = values, RawText = OvpnDocument.FormatTokens(values) };
    }

    public InvalidDataException Error(string message) => new($"{SourcePath}:{LineNumber}: {message}");
}

/// <summary>OpenVPN tokens plus opaque inline data; unchanged nodes retain their original text.</summary>
public sealed class OvpnDocument
{
    public const int MaximumBytes = 4 * 1024 * 1024;
    // OpenVPN 2.7 options_parse.c reads options/inline data into 256-byte buffers.
    // Reserve newline and NUL so no physical line can become two parser inputs.
    public const int MaximumLineLength = 254;
    public IReadOnlyList<OvpnNode> Nodes { get; }
    public string? BaseDirectory { get; }

    public OvpnDocument(IEnumerable<OvpnNode> nodes, string? baseDirectory = null)
    {
        Nodes = nodes.ToArray();
        BaseDirectory = baseDirectory;
    }
    public string Render() => string.Join("\n", Nodes.Select(node => node.RawText)) + "\n";

    public static OvpnDocument Load(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length > MaximumBytes) throw new InvalidDataException($"OpenVPN configuration exceeds {MaximumBytes} bytes: {path}");
        using var reader = new StreamReader(file, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true);
        return Parse(reader.ReadToEnd(), Path.GetFullPath(path));
    }

    public static OvpnDocument Parse(string text, string sourcePath = "<memory>")
    {
        if (Encoding.UTF8.GetByteCount(text) > MaximumBytes) throw new InvalidDataException("OpenVPN configuration is too large.");
        if (text.IndexOf('\0') >= 0) throw new InvalidDataException("OpenVPN configuration contains NUL characters.");
        var lines = text.TrimStart('\uFEFF').Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var count = lines.Length - (lines[^1].Length == 0 ? 1 : 0);
        var nodes = new List<OvpnNode>();
        var connection = false;
        for (var index = 0; index < count; index++)
        {
            var line = lines[index];
            IReadOnlyList<string> tokens;
            try { tokens = Tokenize(line); }
            catch (InvalidDataException error) { throw new InvalidDataException($"{sourcePath}:{index + 1}: {error.Message}", error); }
            var node = new OvpnNode(tokens.Count == 0 ? OvpnNodeKind.Trivia : OvpnNodeKind.Directive,
                line, tokens, sourcePath, index + 1);
            var first = tokens.Count > 0 && tokens[0].StartsWith("--", StringComparison.Ordinal) ? tokens[0][2..] : tokens.FirstOrDefault();
            if (tokens.Count == 1 && first == "<connection>")
            {
                if (connection) throw node.Error("Nested <connection> blocks are not supported.");
                connection = true;
                nodes.Add(node with { Kind = OvpnNodeKind.ConnectionStart });
            }
            else if (tokens.Count == 1 && first == "</connection>")
            {
                if (!connection) throw node.Error("Unexpected </connection>.");
                if (!line.Trim(' ', '\t', '\v', '\f').Equals("</connection>", StringComparison.Ordinal))
                    throw node.Error("The </connection> closing tag must be unquoted and alone on its line.");
                connection = false;
                nodes.Add(node with { Kind = OvpnNodeKind.ConnectionEnd });
            }
            else if (tokens.Count == 1 && first!.StartsWith('<') && first.EndsWith('>'))
            {
                var tag = first[1..^1];
                if (tag.Length == 0 || tag.StartsWith('/') || tag.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
                    throw node.Error("Invalid or unexpected inline-data tag.");
                var closing = "</" + tag + ">";
                var body = new StringBuilder(line);
                var closed = false;
                while (++index < count)
                {
                    CheckLine(lines[index]);
                    if (connection && lines[index].TrimStart(' ', '\t', '\v', '\f').StartsWith("</connection>", StringComparison.Ordinal))
                        throw node.Error("A connection closing tag cannot occur inside inline data.");
                    body.Append('\n').Append(lines[index]);
                    if (lines[index].Trim(' ', '\t', '\v', '\f').Equals(closing, StringComparison.Ordinal)) { closed = true; break; }
                    // OpenVPN accepts a closing-tag prefix; reject ambiguous suffixes instead of
                    // allowing a different boundary in the parser and in the child process.
                    if (lines[index].TrimStart(' ', '\t', '\v', '\f').StartsWith(closing, StringComparison.Ordinal))
                        throw node.Error("An inline closing tag must be alone on its line.");
                }
                if (!closed) throw node.Error($"Missing {closing}.");
                nodes.Add(node with { Kind = OvpnNodeKind.InlineBlock, RawText = body.ToString() });
            }
            else nodes.Add(node);
        }
        if (connection) throw new InvalidDataException($"{sourcePath}: missing </connection>.");
        return new OvpnDocument(nodes, Path.IsPathFullyQualified(sourcePath) ? Path.GetDirectoryName(sourcePath) : null);
    }

    /// <summary>Matches OpenVPN 2.7 options_parse.c, including literal single-quoted backslashes.</summary>
    public static IReadOnlyList<string> Tokenize(string line)
    {
        CheckLine(line);
        var tokens = new List<string>();
        var index = 0;
        while (index < line.Length)
        {
            while (index < line.Length && IsSpace(line[index])) index++;
            if (index == line.Length || line[index] is '#' or ';') break;
            var quote = line[index] is '\'' or '"' ? line[index++] : '\0';
            var value = new StringBuilder();
            var closed = quote == '\0';
            while (index < line.Length)
            {
                var character = line[index++];
                if (quote != '\0' && character == quote) { closed = true; break; }
                if (quote == '\0' && IsSpace(character)) break;
                if (character == '\\' && quote != '\'')
                {
                    if (index == line.Length) throw new InvalidDataException("Trailing backslash escape.");
                    character = line[index++];
                    if (character != '\\' && character != '"' && !IsSpace(character))
                        throw new InvalidDataException("Invalid backslash escape; use doubled backslashes or single quotes for Windows paths.");
                    if (quote == '\0' && value.Length == 0 && IsSpace(character))
                        throw new InvalidDataException("Use quotes instead of a leading escaped space in a parameter.");
                }
                value.Append(character);
            }
            if (!closed) throw new InvalidDataException("Unclosed quoted parameter.");
            tokens.Add(value.ToString());
            if (tokens.Count > 16) throw new InvalidDataException("Too many parameters on one option line (maximum 16).");
        }
        return tokens;
    }

    public static string FormatTokens(IEnumerable<string> tokens)
    {
        var values = tokens.ToArray();
        if (values.Length > 16) throw new InvalidDataException("Too many parameters on one option line (maximum 16).");
        var line = string.Join(" ", values.Select(Quote));
        CheckLine(line);
        return line;
    }

    private static bool IsSpace(char character) => character is ' ' or '\t' or '\v' or '\f';
    private static void CheckLine(string line)
    {
        if (Encoding.UTF8.GetByteCount(line) > MaximumLineLength)
            throw new InvalidDataException($"OpenVPN lines must not exceed {MaximumLineLength} UTF-8 bytes.");
        if (line.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0)
            throw new InvalidDataException("Invalid control character in an option line.");
    }

    public static string Quote(string token)
    {
        if (token.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0) throw new InvalidDataException("A parameter contains line breaks or NUL.");
        return "\"" + token.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }
}
