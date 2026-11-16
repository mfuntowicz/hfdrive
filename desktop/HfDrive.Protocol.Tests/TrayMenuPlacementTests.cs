using HfDrive.Desktop.Services;
using Xunit;

namespace HfDrive.Protocol.Tests;

public sealed class TrayMenuPlacementTests
{
    [Fact]
    public void IconAnchorCentersHorizontallyAndAlignsMenuBottomToIconTop()
    {
        TrayMenuPlacement placement = TrayMenuPlacement.AboveIcon(left: 100, top: 900, right: 133, bottom: 932);

        Assert.Equal(116, placement.X);
        Assert.Equal(900, placement.Y);
        Assert.True(placement.CenterHorizontal);
        Assert.True(placement.AlignBottom);
    }

    [Fact]
    public void PointerFallbackKeepsTheSameAboveAnchorAlignment()
    {
        TrayMenuPlacement placement = TrayMenuPlacement.AbovePoint(240, 700);

        Assert.Equal(240, placement.X);
        Assert.Equal(700, placement.Y);
        Assert.True(placement.CenterHorizontal);
        Assert.True(placement.AlignBottom);
    }
}
