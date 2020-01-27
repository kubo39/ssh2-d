module ssh2.sftp;

private import ssh2.ffi;

class Sftp
{
private:
    LIBSSH2_SFTP* raw;
    LIBSSH2_SESSION* session;

package:
    this(LIBSSH2_SFTP* raw, LIBSSH2_SESSION* session) @nogc nothrow
    {
        this.raw = raw;
        this.session = session;
    }

public:
    ~this() @nogc nothrow
    {
        libssh2_sftp_shutdown(this.raw);
    }
}
