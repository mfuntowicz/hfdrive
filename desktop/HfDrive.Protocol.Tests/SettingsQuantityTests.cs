using HfDrive.Desktop.ViewModels;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>
/// Regression tests for the Settings page's human-readable quantity
/// conversion, compiled from the same <c>SettingsQuantity.cs</c> source the
/// desktop ships. These cover the consumer-visible uncertain edges: every
/// value read from the provider must format and parse back to the identical
/// number (including non-aligned and very large values), IEC units convert
/// exactly, "Unlimited" is zero only for transfer speeds, and fractional
/// bytes, negative amounts and overflow never produce a patch value.
/// </summary>
public sealed class SettingsQuantityTests
{
    /// <summary>18446744073709551615 (the widest unsigned 64-bit value).</summary>
    private const ulong MaxU64 = ulong.MaxValue;

    // ── Formatting: exact, never rounded ────────────────────────────────

    [Theory]
    [InlineData(0UL, "0 B")]
    [InlineData(1UL, "1 B")]
    [InlineData(1000UL, "1000 B")]
    [InlineData(1024UL, "1 KiB")]
    [InlineData(1536UL, "1536 B")]              // not an exact KiB multiple: plain bytes
    [InlineData(524288UL, "512 KiB")]
    [InlineData(10485760UL, "10 MiB")]
    [InlineData(1048576UL, "1 MiB")]
    [InlineData(5368709120UL, "5 GiB")]
    [InlineData(10737418240UL, "10 GiB")]
    [InlineData(2199023255552UL, "2 TiB")]
    [InlineData(4294967296UL, "4 GiB")]
    [InlineData(1125899906842624UL, "1 PiB")]
    [InlineData(1152921504606846976UL, "1 EiB")]
    [InlineData(13835058055282163712UL, "12 EiB")]
    public void Format_UsesExactLargestIecUnit(ulong bytes, string expected)
    {
        Assert.Equal(expected, SettingsQuantity.Format(bytes));
    }

    [Fact]
    public void Format_NonAlignedVeryLargeValue_FallsBackToPlainBytes()
    {
        // 2^64 - 1 is not an exact multiple of any unit beyond bytes.
        Assert.Equal("18446744073709551615 B", SettingsQuantity.Format(MaxU64));
    }

    // ── Round trips: read -> display -> read is always the same number ──

    [Theory]
    [InlineData(0UL)]
    [InlineData(1UL)]
    [InlineData(1536UL)]
    [InlineData(4095UL)]
    [InlineData(10485760UL)]
    [InlineData(4294967296UL)]
    [InlineData(1152921504606846976UL)]
    [InlineData(13835058055282163712UL)]
    [InlineData(MaxU64)]
    public void FormatThenParse_ReturnsTheIdenticalValue(ulong bytes)
    {
        string text = SettingsQuantity.Format(bytes);
        Assert.True(
            SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong parsed, out SettingsQuantityError error),
            $"\"{text}\" should parse back ({error})");
        Assert.Equal(SettingsQuantityError.None, error);
        Assert.Equal(bytes, parsed);
    }

    [Fact]
    public void FormatThenParse_RoundTripsEveryExactUnitBoundary()
    {
        for (int exponent = 0; exponent <= 6; exponent++)
        {
            ulong factor = 1UL << (10 * exponent);
            foreach (ulong multiple in new ulong[] { 1, 3, 15, 1023 })
            {
                if (multiple > ulong.MaxValue / factor)
                    continue; // outside the provider's u64 range
                ulong bytes = multiple * factor;
                string text = SettingsQuantity.Format(bytes);
                Assert.True(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong parsed, out _));
                Assert.Equal(bytes, parsed);
            }
        }
    }

    // ── Parsing: IEC units convert exactly ──────────────────────────────

    [Theory]
    [InlineData("0", 0UL)]
    [InlineData("0 B", 0UL)]
    [InlineData("1024", 1024UL)]
    [InlineData("1 KiB", 1024UL)]
    [InlineData("1 KiB/s", 1024UL)]
    [InlineData("10 MiB/s", 10485760UL)]
    [InlineData("10 MiB", 10485760UL)]
    [InlineData("512 MiB", 536870912UL)]
    [InlineData("512 KiB", 524288UL)]
    [InlineData("10 GiB", 10737418240UL)]
    [InlineData("1 TiB", 1099511627776UL)]
    [InlineData("1 PiB", 1125899906842624UL)]
    [InlineData("1 EiB", 1152921504606846976UL)]
    [InlineData("15 EiB", 17293822569102704640UL)]
    [InlineData("18446744073709551615 B", MaxU64)]
    [InlineData("18446744073709551615", MaxU64)]
    public void Parse_IecUnits_ConvertExactly(string text, ulong expected)
    {
        Assert.True(
            SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong value, out SettingsQuantityError error),
            $"\"{text}\" should parse ({error})");
        Assert.Equal(SettingsQuantityError.None, error);
        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData("1.5 KiB", 1536UL)]
    [InlineData("1.25 MiB", 1310720UL)]
    [InlineData("2.5 GiB", 2684354560UL)]
    [InlineData("1.5KiB", 1536UL)]
    [InlineData("1.5 MiB/s", 1572864UL)]
    [InlineData("0.5 EiB", 576460752303423488UL)]
    [InlineData("0.25 KiB", 256UL)]
    public void Parse_DecimalQuantities_ResolveToExactBytes(string text, ulong expected)
    {
        Assert.True(
            SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong value, out SettingsQuantityError error),
            $"\"{text}\" should parse ({error})");
        Assert.Equal(SettingsQuantityError.None, error);
        Assert.Equal(expected, value);
    }

    // ── Unlimited: transfer speeds only, zero semantics preserved ───────

    [Theory]
    [InlineData("Unlimited")]
    [InlineData("unlimited")]
    [InlineData("  UNLIMITED  ")]
    public void Parse_Unlimited_RateOnly_StoresZero(string text)
    {
        Assert.True(SettingsQuantity.TryParse(text, SettingsQuantityKind.Rate, out ulong value, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.None, error);
        Assert.Equal(0UL, value);
        Assert.True(SettingsQuantity.IsUnlimited(text));
    }

    [Fact]
    public void Parse_Unlimited_IsNeverASize()
    {
        Assert.False(SettingsQuantity.TryParse("Unlimited", SettingsQuantityKind.Size, out ulong value, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.UnlimitedNotAllowed, error);
        Assert.Equal(0UL, value);
        Assert.False(SettingsQuantity.IsUnlimited("512 MiB"));
    }

    [Theory]
    [InlineData("0 B")]
    [InlineData("0")]
    [InlineData("0 KiB")]
    public void Parse_ZeroByteValues_StayZero(string text)
    {
        // Zero is a real value for byte budgets, never the Unlimited word.
        Assert.True(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong size, out _));
        Assert.Equal(0UL, size);
        Assert.True(SettingsQuantity.TryParse(text, SettingsQuantityKind.Rate, out ulong rate, out _));
        Assert.Equal(0UL, rate);
    }

    // ── Rejections: fractional bytes, negatives, overflow, malformed ────

    [Theory]
    [InlineData("0.5 B")]
    [InlineData("1.5 B")]
    [InlineData("1.0000000000000000001 EiB")]
    public void Parse_FractionalBytes_IsRejected(string text)
    {
        // "0.5 B" is a fraction of one byte, not an exact zero: the value is
        // never truncated or rounded to make the input fit.
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out ulong value, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.FractionalBytes, error);
        Assert.Equal(0UL, value);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("-5 MiB")]
    [InlineData("\u22121 KiB")]
    [InlineData("-0")]
    public void Parse_NegativeAmounts_AreRejected(string text)
    {
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out _, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.Negative, error);
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Rate, out _, out SettingsQuantityError rateError));
        Assert.Equal(SettingsQuantityError.Negative, rateError);
    }

    [Theory]
    [InlineData("18446744073709551616 B")]      // 2^64
    [InlineData("16 EiB")]                      // 2^64 exactly
    [InlineData("18446744073709551616")]
    [InlineData("99999999999999999999999 GiB")]
    public void Parse_ValuesBeyondUnsigned64Bits_AreOverflow(string text)
    {
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out _, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.Overflow, error);
    }

    [Fact]
    public void Parse_BoundaryIsExact_UlongMaxAndOneBelow()
    {
        Assert.True(SettingsQuantity.TryParse("15 EiB", SettingsQuantityKind.Size, out ulong fifteenEiB, out _));
        Assert.Equal(17293822569102704640UL, fifteenEiB);
        Assert.True(SettingsQuantity.TryParse("18446744073709551615", SettingsQuantityKind.Size, out ulong max, out _));
        Assert.Equal(MaxU64, max);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_EmptyText_IsEmpty_NotZero(string text)
    {
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out _, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.Empty, error);
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Rate, out _, out SettingsQuantityError rateError));
        Assert.Equal(SettingsQuantityError.Empty, rateError);
    }

    [Theory]
    [InlineData("banana")]
    [InlineData("MiB")]
    [InlineData("10 MB")]
    [InlineData("10 bytes")]
    [InlineData("1..5 MiB")]
    [InlineData("1. MiB")]
    [InlineData(".5 MiB")]
    [InlineData("1.2.3 MiB")]
    [InlineData("0x10")]
    [InlineData("1e9")]
    [InlineData("+5 MiB")]
    public void Parse_MalformedText_IsRejected(string text)
    {
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Size, out _, out SettingsQuantityError error));
        Assert.Equal(SettingsQuantityError.Malformed, error);
        Assert.False(SettingsQuantity.TryParse(text, SettingsQuantityKind.Rate, out _, out SettingsQuantityError rateError));
        Assert.Equal(SettingsQuantityError.Malformed, rateError);
    }

    // ── Rate display: kind-aware, zero semantics preserved ──────────────

    [Fact]
    public void FormatValue_Rates_ShowUnlimitedAtZeroAndPerSecondOtherwise()
    {
        Assert.Equal("Unlimited", SettingsQuantity.FormatValue(0, SettingsQuantityKind.Rate));
        Assert.Equal("10 MiB/s", SettingsQuantity.FormatValue(10485760UL, SettingsQuantityKind.Rate));
        Assert.Equal("512 KiB/s", SettingsQuantity.FormatValue(524288UL, SettingsQuantityKind.Rate));
        Assert.Equal("1536 B/s", SettingsQuantity.FormatValue(1536UL, SettingsQuantityKind.Rate));
    }

    [Fact]
    public void FormatValue_Sizes_KeepPlainBytesAndExactZero()
    {
        Assert.Equal("0 B", SettingsQuantity.FormatValue(0, SettingsQuantityKind.Size));
        Assert.Equal("512 MiB", SettingsQuantity.FormatValue(536870912UL, SettingsQuantityKind.Size));
    }

    // ── Dirty detection and draft rebase across a moving baseline ───────

    [Fact]
    public void DiffersFrom_BlankAndEquivalentTextsAreNotDirty()
    {
        // Blank always means "keep stored"; an equivalent unit spelling of the
        // stored value is not an edit.
        Assert.False(SettingsQuantity.DiffersFrom("", SettingsQuantityKind.Size, 536870912UL));
        Assert.False(SettingsQuantity.DiffersFrom("   ", SettingsQuantityKind.Size, 536870912UL));
        Assert.False(SettingsQuantity.DiffersFrom("512 MiB", SettingsQuantityKind.Size, 536870912UL));
        Assert.False(SettingsQuantity.DiffersFrom("0.5 KiB", SettingsQuantityKind.Size, 512UL));
        Assert.False(SettingsQuantity.DiffersFrom("Unlimited", SettingsQuantityKind.Rate, 0UL));
    }

    [Fact]
    public void DiffersFrom_ChangedOrInvalidTextsAreDirty()
    {
        Assert.True(SettingsQuantity.DiffersFrom("10 MiB/s", SettingsQuantityKind.Rate, 0UL));
        Assert.True(SettingsQuantity.DiffersFrom("banana", SettingsQuantityKind.Size, 512UL));
        Assert.True(SettingsQuantity.DiffersFrom("0.5 B", SettingsQuantityKind.Size, 0UL));
        // A field whose value is not stored becomes dirty with any real input.
        Assert.True(SettingsQuantity.DiffersFrom("512 MiB", SettingsQuantityKind.Size, null));
    }

    [Fact]
    public void RebaseDraft_UntouchedFieldAdoptsTheNewRemoteValue()
    {
        // Main's regression: the user edits only the rate; another client moves
        // the cache baseline 512 MiB -> 1 GiB. The untouched cache field must
        // adopt 1 GiB and must not become an edit back to 512 MiB.
        string rate = SettingsQuantity.RebaseDraft("10 MiB/s", SettingsQuantityKind.Rate, 0UL, 0UL);
        string cache = SettingsQuantity.RebaseDraft("512 MiB", SettingsQuantityKind.Size, 536870912UL, 10737418240UL);
        Assert.Equal("10 MiB/s", rate);
        Assert.Equal("10 GiB", cache);
    }

    [Fact]
    public void RebaseDraft_ChangedRemoteValueWithUneditedOrBlankDraftAdoptsFreshValue()
    {
        // Unedited text that still equals the old baseline is not a draft edit.
        Assert.Equal("1 GiB", SettingsQuantity.RebaseDraft("512 MiB", SettingsQuantityKind.Size, 536870912UL, 1073741824UL));
        // Blank means "keep stored": after the baseline moves it shows the new value.
        Assert.Equal("1 GiB", SettingsQuantity.RebaseDraft("", SettingsQuantityKind.Size, 536870912UL, 1073741824UL));
        Assert.Equal("10 MiB/s", SettingsQuantity.RebaseDraft("", SettingsQuantityKind.Rate, 0UL, 10485760UL));
        // Rate zero displays as the Unlimited word, never "0 B".
        Assert.Equal("Unlimited", SettingsQuantity.RebaseDraft("", SettingsQuantityKind.Rate, 10485760UL, 0UL));
    }

    [Fact]
    public void RebaseDraft_EquivalentUnitDraftIsNotDirtyAndAdoptsFreshValue()
    {
        // "0.5 KiB" is exactly the stored 512 B, so the field carries no edit
        // and adopts whatever the provider now stores.
        Assert.Equal("1 KiB", SettingsQuantity.RebaseDraft("0.5 KiB", SettingsQuantityKind.Size, 512UL, 1024UL));
    }

    [Fact]
    public void RebaseDraft_KeepsUserEditedTextIncludingInvalidDrafts()
    {
        // A real edit survives a baseline change verbatim…
        Assert.Equal("2 GiB", SettingsQuantity.RebaseDraft("2 GiB", SettingsQuantityKind.Size, 1073741824UL, 536870912UL));
        // …and invalid text stays exactly as typed for correction.
        Assert.Equal("banana", SettingsQuantity.RebaseDraft("banana", SettingsQuantityKind.Size, 1024UL, 2048UL));
        Assert.Equal("0.5 B", SettingsQuantity.RebaseDraft("0.5 B", SettingsQuantityKind.Size, 1024UL, 2048UL));
        // A dirty field against a previously un-stored key is kept too.
        Assert.Equal("512 MiB", SettingsQuantity.RebaseDraft("512 MiB", SettingsQuantityKind.Size, null, 1024UL));
    }

    [Fact]
    public void RebaseDraft_ARemovedKeyClearsUntouchedFieldsButKeepsDirtyOnes()
    {
        Assert.Equal("", SettingsQuantity.RebaseDraft("512 MiB", SettingsQuantityKind.Size, 536870912UL, null));
        Assert.Equal("512 MiB", SettingsQuantity.RebaseDraft("512 MiB", SettingsQuantityKind.Size, 1073741824UL, null));
    }
}
