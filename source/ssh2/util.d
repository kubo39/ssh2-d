module ssh2.util;

struct Dimension
{
    uint width;
    uint height;
    uint width_px;
    uint height_px;
}

/// Encodes modes for Pty allocation requests.
/// The modes documented in <https://tools.ietf.org/html/rfc4250#section-4.5>
struct PtyModes
{
    ubyte[] data;
    alias data this;
}
