module ssh2.channel;

private import ssh2.ffi;
import ssh2.exception;
import ssh2.session;

import std.range : isOutputRange;

/// Stream ID of the stderr channel.
private static int EXTENDED_DATA_STDERR = 1;

/// How to handle extended data
enum ExtendedData
{
    NORMAL = LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL,
    IGNORE = LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE,
    MERGE = LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE,
}

/// A channel represents a portion of SSH connection.
class Channel
{
private:
    LIBSSH2_CHANNEL* raw;
    LIBSSH2_SESSION* session;

package:
    this(LIBSSH2_CHANNEL* raw, LIBSSH2_SESSION* session) @nogc nothrow pure
    {
        this.raw = raw;
        this.session = session;
    }

public:
    ~this()
    {
        libssh2_channel_free(this.raw);
    }

    /// Execute command.
    void exec(string command)
    {
        this.processStartup("exec", command);
    }

    /// Initiate request on a session type channel.
    void processStartup(string request, string message)
    {
        import std.string : toStringz;
        const msg = message.length ? message.toStringz : null;
        auto rc = libssh2_channel_process_startup(
            this.raw,
            request.toStringz,
            cast(uint) request.length,
            msg,
            cast(uint) message.length);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Get a handle to the stderr stream.
    Stream stderr()
    {
        return new Stream(this, EXTENDED_DATA_STDERR);
    }

    /// Get a handle to particular stream.
    Stream stream(int streamId)
    {
        return new Stream(this, streamId);
    }

    void flush()
    {
        this.stream(0).flush();
    }

    size_t read(ubyte[] buffer)
    {
        return this.stream(0).read(buffer);
    }

    size_t write(string buffer)
    {
        return this.stream(0).write(cast(const ubyte[]) buffer);
    }

    void waitEOF()
    {
        auto rc = libssh2_channel_wait_eof(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    bool eof() @nogc nothrow
    {
        return libssh2_channel_eof(this.raw) != 0;
    }

    /// Tell the remote host that no futher data will be sent on.
    void sendEOF()
    {
        auto rc = libssh2_channel_send_eof(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Close an active data channel.
    void close()
    {
        auto rc = libssh2_channel_close(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Temporary blocking state until the remote host closes the
    /// named channel.
    void waitClosed()
    {
        auto rc = libssh2_channel_wait_closed(this.raw);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Returns the exit code raised by the process running on the
    /// remote host.
    int exitStatus() @nogc nothrow
    {
        return libssh2_channel_get_exit_status(this.raw);
    }

    /// Change how extended data is handled.
    void handleExtendedData(ExtendedData mode)
    {
        auto rc = libssh2_channel_handle_extended_data2(this.raw, mode);
        if (rc < 0)
            throw new SessionError(this.session, rc);
    }

    /// Adjust the receive window for a channel.
    ulong adjustReceiveWindow(ulong adjust, bool force)
    {
        uint ret;
        auto rc = libssh2_channel_receive_window_adjust2(
            this.raw,
            adjust,
            cast(ubyte) force,
            &ret);
        if (rc < 0)
            throw new SessionError(this.session, rc);
        return cast(ulong) ret;
    }
}


class Stream
{
private:
    Channel channel;
    int id;

public:
    this(Channel channel, int id) @nogc nothrow pure
    {
        this.channel = channel;
        this.id = id;
    }

    void flush()
    {
        auto rc = libssh2_channel_flush_ex(this.channel.raw, this.id);
        if (rc < 0)
            throw new SessionError(this.channel.session, rc);
    }

    size_t read(ubyte[] data)
    {
        if (this.channel.eof())
            return 0;
        auto rc = libssh2_channel_read_ex(
            this.channel.raw,
            this.id,
            data.ptr,
            data.length);
        if (rc < 0)
            throw new SessionError(this.channel.session, cast(int) rc);
        return cast(size_t) rc;
    }

    size_t write(const ubyte[] data)
    {
        auto rc = libssh2_channel_write_ex(
            this.channel.raw,
            this.id,
            data.ptr,
            data.length);
        if (rc < 0)
            throw new SessionError(this.channel.session, cast(int) rc);
        return rc;
    }
}
