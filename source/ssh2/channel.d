module ssh2.channel;

private import ssh2.ffi;
import ssh2.exception;
import ssh2.session;

import std.range : isOutputRange;

/// Stream ID of the stderr channel.
private static int EXTENDED_DATA_STDERR = 1;

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
}
