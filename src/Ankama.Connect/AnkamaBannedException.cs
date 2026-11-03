namespace Ankama.Connect;

public sealed class AnkamaBannedException : Exception
{
    public AnkamaBannedException()
        : base("Ankama reports a banned account.")
    {
    }
}
