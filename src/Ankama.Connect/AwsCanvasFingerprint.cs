using System.Text.Json.Nodes;
using SkiaSharp;

namespace Ankama.Connect;

internal static class AwsCanvasFingerprint
{
    private const int Width = 150;
    private const int Height = 60;

    internal static JsonObject Create(JsonObject math)
    {
        using var surface = SKSurface.Create(
            new SKImageInfo(Width, Height, SKColorType.Rgba8888, SKAlphaType.Premul));
        Draw(surface.Canvas, math);

        using var image = surface.Snapshot();
        using var encoded = image.Encode(SKEncodedImageFormat.Png, 100);
        var dataUrl = "data:image/png;base64," + Convert.ToBase64String(encoded.ToArray());

        using var bitmap = new SKBitmap(
            new SKImageInfo(Width, Height, SKColorType.Rgba8888, SKAlphaType.Premul));
        image.ReadPixels(bitmap.Info, bitmap.GetPixels(), bitmap.RowBytes, 0, 0);
        var pixels = bitmap.Bytes;

        var bins = new int[256];
        foreach (var value in pixels)
            bins[value]++;

        var histogram = new JsonArray();
        foreach (var value in bins)
            histogram.Add(value);

        return new JsonObject
        {
            ["hash"] = unchecked((int)AwsCrc32.ComputeUInt32(dataUrl)),
            ["emailHash"] = null,
            ["histogramBins"] = histogram
        };
    }

    private static void Draw(SKCanvas canvas, JsonObject math)
    {
        canvas.Clear(SKColors.Transparent);

        using var fill = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Fill };
        using var stroke = new SKPaint { IsAntialias = true, Style = SKPaintStyle.Stroke, StrokeWidth = 1 };

        fill.Color = SKColor.Parse("#f60");
        canvas.DrawRect(125, 1, 62, 20, fill);

        using var arial = SKTypeface.FromFamilyName("Arial");
        using var smallFont = new SKFont(arial, PointsToPixels(8));
        using var mediumFont = new SKFont(arial, PointsToPixels(11));
        using var fallbackFont = new SKFont(SKTypeface.Default, PointsToPixels(10));

        fill.Color = SKColor.Parse("#069");
        canvas.DrawText("Cwm fjordbank glyphs vext quiz,", 2, 15, SKTextAlign.Left, smallFont, fill);

        fill.Color = new SKColor(102, 204, 0, 51);
        canvas.DrawText("Cwm fjordbank glyphs vext quiz,", 4, 45, SKTextAlign.Left, mediumFont, fill);

        fill.BlendMode = SKBlendMode.Multiply;
        DrawCircle(canvas, 20, 20, 20, SKColors.Magenta, fill);
        DrawCircle(canvas, 50, 20, 20, SKColors.Cyan, fill);
        DrawCircle(canvas, 35, 40, 20, SKColors.Yellow, fill);

        using var evenOddPathBuilder = new SKPathBuilder { FillType = SKPathFillType.EvenOdd };
        evenOddPathBuilder.AddCircle(20, 25, 10);
        evenOddPathBuilder.AddCircle(20, 25, 20);
        using var evenOddPath = BuildPath(evenOddPathBuilder);
        fill.Color = SKColors.Magenta;
        canvas.DrawPath(evenOddPath, fill);

        using var gradientShader = SKShader.CreateLinearGradient(
            new SKPoint(40, 50),
            new SKPoint(60, 78),
            [SKColors.Blue, SKColors.Red, SKColors.White],
            [0f, 0.5f, 1f],
            SKShaderTileMode.Clamp);
        fill.Shader = gradientShader;
        DrawCirclePath(canvas, 70, 50, 10, fill);
        fill.Shader = null;

        stroke.Color = SKColors.Black;
        canvas.DrawText(math["tan"]!.GetValue<string>(), 4, 30, SKTextAlign.Left, fallbackFont, stroke);
        canvas.DrawText(math["cos"]!.GetValue<string>(), 4, 40, SKTextAlign.Left, fallbackFont, fill);
        canvas.DrawText(math["sin"]!.GetValue<string>(), 4, 50, SKTextAlign.Left, fallbackFont, fill);

        using var pathBuilder = new SKPathBuilder();
        pathBuilder.MoveTo(25, 0);
        pathBuilder.QuadTo(1, 1, 1, 5);
        pathBuilder.QuadTo(1, 76, 26, 10);
        pathBuilder.QuadTo(26, 96, 6, 12);
        pathBuilder.QuadTo(60, 96, 41, 10);
        pathBuilder.QuadTo(121, 86, 101, 7);
        pathBuilder.QuadTo(121, 1, 56, 1);
        using var path = BuildPath(pathBuilder);
        canvas.DrawPath(path, stroke);

        fill.BlendMode = SKBlendMode.Difference;
        fill.Color = SKColors.Magenta;
        DrawCirclePath(canvas, 80, 20, 20, fill);
        fill.Color = SKColors.Cyan;
        DrawCirclePath(canvas, 110, 20, 20, fill);
        fill.Color = SKColors.Yellow;
        DrawCirclePath(canvas, 95, 40, 20, fill);
    }

    private static void DrawCircle(
        SKCanvas canvas,
        float x,
        float y,
        float radius,
        SKColor color,
        SKPaint paint)
    {
        paint.Color = color;
        DrawCirclePath(canvas, x, y, radius, paint);
    }

    private static void DrawCirclePath(SKCanvas canvas, float x, float y, float radius, SKPaint paint)
    {
        using var pathBuilder = new SKPathBuilder();
        pathBuilder.AddCircle(x, y, radius);
        using var path = BuildPath(pathBuilder);
        canvas.DrawPath(path, paint);
    }

    private static SKPath BuildPath(SKPathBuilder builder)
        => builder.Detach();

    private static float PointsToPixels(float points)
        => points * 96f / 72f;
}
