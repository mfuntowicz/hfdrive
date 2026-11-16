using System.Globalization;
using System.Numerics;

namespace HfDrive.Desktop.ViewModels;

/// <summary>
/// Which of the provider's settings a quantity box edits. Only transfer
/// speeds accept "Unlimited" (the provider's zero means "no limit"); every
/// other setting is a byte budget where zero is a real numeric value.
/// </summary>
public enum SettingsQuantityKind
{
    /// <summary>A transfer rate in bytes per second (0 = Unlimited).</summary>
    Rate,
    /// <summary>A byte budget or reserve where 0 is a real value.</summary>
    Size,
}

/// <summary>Why one settings quantity text could not become a value.</summary>
public enum SettingsQuantityError
{
    /// <summary>The text parsed successfully.</summary>
    None,
    /// <summary>No text entered; the field keeps its stored value.</summary>
    Empty,
    /// <summary>The text is not a valid quantity.</summary>
    Malformed,
    /// <summary>A fraction of a byte cannot be stored as a byte count.</summary>
    FractionalBytes,
    /// <summary>A negative amount is not a valid setting.</summary>
    Negative,
    /// <summary>The amount exceeds the provider's unsigned 64-bit range.</summary>
    Overflow,
    /// <summary>"Unlimited" was entered on a setting that must be a byte amount.</summary>
    UnlimitedNotAllowed,
}

/// <summary>
/// Pure, dependency-free exact conversion between the provider's unsigned
/// 64-bit settings values and the human-readable IEC quantity text shown on
/// the Settings page. All arithmetic is exact integer arithmetic (no floating
/// point), so a value read from the provider always formats and parses back to
/// the identical number.
/// </summary>
public static class SettingsQuantity
{
    /// <summary>Word accepted (case-insensitively) for an unlimited transfer rate.</summary>
    public const string UnlimitedWord = "Unlimited";

    private static readonly string[] UnitNames =
        { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };

    /// <summary>
    /// Formats an exact stored byte value as an IEC quantity, choosing the
    /// largest unit that divides it exactly. Values that are not an exact
    /// multiple of a larger unit (for example 1536) fall back to plain bytes,
    /// so the display never rounds away stored data.
    /// </summary>
    public static string Format(ulong bytes)
    {
        if (bytes == 0)
            return "0 B"; // zero is a plain byte count in every unit context
        for (int exponent = UnitNames.Length - 1; exponent >= 1; exponent--)
        {
            ulong factor = 1UL << (10 * exponent);
            if (bytes % factor == 0)
            {
                // The quotient is exact (the modulo check above) and at most
                // 17 decimal digits, so no rounding can ever occur here.
                return (bytes / factor).ToString(CultureInfo.InvariantCulture) + " " + UnitNames[exponent];
            }
        }
        return bytes.ToString(CultureInfo.InvariantCulture) + " B";
    }

    /// <summary>
    /// Parses one human-readable quantity into the exact unsigned 64-bit value
    /// the provider stores. Accepted forms are plain byte digits ("1024", "0")
    /// or an integer or decimal number with an IEC unit ("10 MiB/s", "1.5 GiB",
    /// "512 KiB"); the "/s" suffix is allowed for rates and is informational
    /// only. <see cref="SettingsQuantityKind.Rate"/> additionally accepts the
    /// word "Unlimited" (the provider's zero). Empty text is reported as
    /// <see cref="SettingsQuantityError.Empty"/> and never produces a value.
    /// </summary>
    public static bool TryParse(string? text, SettingsQuantityKind kind, out ulong value, out SettingsQuantityError error)
    {
        value = 0;
        error = SettingsQuantityError.None;
        string trimmed = (text ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            error = SettingsQuantityError.Empty;
            return false;
        }

        if (trimmed.Equals(UnlimitedWord, StringComparison.OrdinalIgnoreCase))
        {
            if (kind == SettingsQuantityKind.Rate)
                return true;
            error = SettingsQuantityError.UnlimitedNotAllowed;
            return false;
        }

        // Negative amounts are rejected before any number parsing, so "-5 MiB"
        // is never mistaken for a malformed positive quantity.
        if (trimmed[0] == '-' || trimmed[0] == '\u2212')
        {
            error = SettingsQuantityError.Negative;
            return false;
        }

        // Split "10 MiB/s" into number "10" and unit "MiB/s".
        int split = 0;
        while (split < trimmed.Length && (char.IsAsciiDigit(trimmed[split]) || trimmed[split] == '.'))
            split++;
        string numberText = trimmed[..split];
        string unitText = trimmed[split..].Trim();
        if (unitText.EndsWith("/s", StringComparison.OrdinalIgnoreCase))
            unitText = unitText[..^2].Trim();
        if (numberText.Length == 0)
        {
            error = SettingsQuantityError.Malformed;
            return false;
        }

        // Split "1.5" into whole "1" and fractional "5"; an integer has no dot.
        string wholeText = numberText;
        string fractionText = string.Empty;
        int dot = numberText.IndexOf('.');
        if (dot >= 0)
        {
            wholeText = numberText[..dot];
            fractionText = numberText[(dot + 1)..];
        }
        bool hasFractionDigits = fractionText.Length != 0;
        if (dot >= 0 && (!hasFractionDigits || wholeText.Length == 0))
        {
            error = SettingsQuantityError.Malformed;
            return false;
        }
        // Exact rational arithmetic: the value is
        // numerator * 2^(10*exponent) / 10^fractionDigits. BigInteger keeps the
        // classification exact: a non-integer result is a fractional byte, and
        // only an integer result beyond u64 is an overflow.
        if (!IsAllDigits(wholeText) || !IsAllDigits(fractionText))
        {
            error = SettingsQuantityError.Malformed;
            return false;
        }
        if (!TryParseUnit(unitText, out int exponent))
        {
            error = SettingsQuantityError.Malformed;
            return false;
        }

        BigInteger numerator = BigInteger.Parse(wholeText + fractionText, CultureInfo.InvariantCulture);
        BigInteger scaled = numerator << (10 * exponent);

        if (!hasFractionDigits)
        {
            if (scaled > ulong.MaxValue)
            {
                error = SettingsQuantityError.Overflow;
                return false;
            }
            value = (ulong)scaled;
            return true;
        }

        BigInteger denominator = BigInteger.Pow(10, fractionText.Length);
        if (scaled % denominator != 0)
        {
            // "1.5 B" is a fraction of one byte; it cannot be stored.
            error = SettingsQuantityError.FractionalBytes;
            return false;
        }
        BigInteger quotient = scaled / denominator;
        if (quotient > ulong.MaxValue)
        {
            error = SettingsQuantityError.Overflow;
            return false;
        }
        value = (ulong)quotient;
        return true;
    }

    /// <summary>
    /// Formats one stored value the way the Settings page shows it. Rates are
    /// the "Unlimited" word at zero and carry a "/s" suffix otherwise; sizes
    /// are plain byte quantities where zero stays "0 B".
    /// </summary>
    public static string FormatValue(ulong value, SettingsQuantityKind kind)
    {
        if (kind == SettingsQuantityKind.Rate)
            return value == 0 ? UnlimitedWord : Format(value) + "/s";
        return Format(value);
    }

    /// <summary>True when the text is exactly the "Unlimited" word.</summary>
    public static bool IsUnlimited(string? text) =>
        (text ?? string.Empty).Trim().Equals(UnlimitedWord, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the draft text represents an unsaved change against the given
    /// stored baseline. Blank is always "keep stored" (never a change), an
    /// equivalent unit spelling of the stored value is not a change, and text
    /// that does not parse is a change the user still has to be able to
    /// correct — it is never silently dropped.
    /// </summary>
    public static bool DiffersFrom(string? text, SettingsQuantityKind kind, ulong? storedValue)
    {
        string trimmed = (text ?? string.Empty).Trim();
        if (trimmed.Length == 0)
            return false;
        if (!TryParse(trimmed, kind, out ulong value, out _))
            return true; // invalid text is the user's draft; keep it for correction
        return storedValue is not { } stored || value != stored;
    }

    /// <summary>
    /// Decides the draft text after the stored baseline moves from
    /// <paramref name="previousValue"/> to <paramref name="currentValue"/> (a
    /// reload or a revision-conflict refresh). A field that carried unsaved
    /// changes against the previous baseline keeps its exact text — including
    /// invalid text awaiting correction. Every other field adopts the fresh
    /// stored value (blank when the key is no longer stored), so an untouched
    /// field can never turn into an edit of the stale value.
    /// </summary>
    public static string RebaseDraft(
        string? draft,
        SettingsQuantityKind kind,
        ulong? previousValue,
        ulong? currentValue)
    {
        if (DiffersFrom(draft, kind, previousValue))
            return draft ?? string.Empty;
        return currentValue is { } value ? FormatValue(value, kind) : string.Empty;
    }

    private static bool IsAllDigits(string text)
    {
        foreach (char c in text)
        {
            if (!char.IsAsciiDigit(c))
                return false;
        }
        return true;
    }

    private static bool TryParseUnit(string unit, out int exponent)
    {
        exponent = 0;
        if (unit.Length == 0)
            return true; // plain byte count
        for (int i = 0; i < UnitNames.Length; i++)
        {
            if (unit.Equals(UnitNames[i], StringComparison.OrdinalIgnoreCase))
            {
                exponent = i;
                return true;
            }
        }
        return false;
    }
}
