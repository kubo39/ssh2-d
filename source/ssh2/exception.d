module ssh2.exception;

private import ssh2.ffi;


/// Exception of an error thar can occur within libssh2.
class SessionError : Exception
{
    this(LIBSSH2_SESSION* raw, int rc,
         string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        import std.string : fromStringz;
        char* msg;
        const res = libssh2_session_last_error(raw, &msg, null, 0);
        if (res != rc)
        {
            throw new SessionErrnoException(rc);
        }
        string s = cast(immutable) msg.fromStringz;
        super(s, file, line, next);
    }
}


/// Exception from an error code from libssh2.
class SessionErrnoException : Exception
{
    this(int code, string file = __FILE__, size_t line = __LINE__,
         Throwable next = null) @nogc nothrow
    {
        string msg;

        // Constructor calls not allowed after label.
        if (code == LIBSSH2_ERROR_BANNER_RECV)
            msg = "banner recv failure";
        else if (code == LIBSSH2_ERROR_BANNER_SEND)
            msg = "banner send failure";
        else if (code == LIBSSH2_ERROR_INVALID_MAC)
            msg = "invalid mac";
        else if (code == LIBSSH2_ERROR_KEX_FAILURE)
            msg = "kex failure";
        else if (code == LIBSSH2_ERROR_ALLOC)
            msg = "alloc failure";
        else if (code == LIBSSH2_ERROR_SOCKET_SEND)
            msg = "socket send faiulre";
        else if (code == LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE)
            msg = "key exchange failure";
        else if (code == LIBSSH2_ERROR_TIMEOUT)
            msg = "timed out";
        else if (code == LIBSSH2_ERROR_HOSTKEY_INIT)
            msg = "hostkey init error";
        else if (code == LIBSSH2_ERROR_HOSTKEY_SIGN)
            msg = "hostkey sign error";
        else if (code == LIBSSH2_ERROR_DECRYPT)
            msg = "decrypt error";
        else if (code == LIBSSH2_ERROR_SOCKET_DISCONNECT)
            msg = "socket disconnected";
        else if (code == LIBSSH2_ERROR_PROTO)
            msg = "protocol error";
        else if (code == LIBSSH2_ERROR_PASSWORD_EXPIRED)
            msg = "password expired";
        else if (code == LIBSSH2_ERROR_FILE)
            msg = "file error";
        else if (code == LIBSSH2_ERROR_METHOD_NONE)
            msg = "bad method name";
        else if (code == LIBSSH2_ERROR_AUTHENTICATION_FAILED)
            msg = "authentication failed";
        else if (code == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED)
            msg = "public key unverified";
        else if (code == LIBSSH2_ERROR_CHANNEL_OUTOFORDER)
            msg = "channel out of order";
        else if (code == LIBSSH2_ERROR_CHANNEL_FAILURE)
            msg = "channel failure";
        else if (code == LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED)
            msg = "request denied";
        else if (code == LIBSSH2_ERROR_CHANNEL_UNKNOWN)
            msg = "unknown channel error";
        else if (code == LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED)
            msg = "window exceeded";
        else if (code == LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED)
            msg = "packet exceeded";
        else if (code == LIBSSH2_ERROR_CHANNEL_CLOSED)
            msg = "closed channel";
        else if (code == LIBSSH2_ERROR_CHANNEL_EOF_SENT)
            msg = "eof sent";
        else if (code == LIBSSH2_ERROR_SCP_PROTOCOL)
            msg = "scp protocol error";
        else if (code == LIBSSH2_ERROR_ZLIB)
            msg = "zlib error";
        else if (code == LIBSSH2_ERROR_SOCKET_TIMEOUT)
            msg = "socket timeout";
        else if (code == LIBSSH2_ERROR_SFTP_PROTOCOL)
            msg = "sftp protocol error";
        else if (code == LIBSSH2_ERROR_REQUEST_DENIED)
            msg = "request denied";
        else if (code == LIBSSH2_ERROR_METHOD_NOT_SUPPORTED)
            msg = "method not supported";
        else if (code == LIBSSH2_ERROR_INVAL)
            msg = "invalid";
        else if (code == LIBSSH2_ERROR_INVALID_POLL_TYPE)
            msg = "invalid poll type";
        else if (code == LIBSSH2_ERROR_PUBLICKEY_PROTOCOL)
            msg = "public key protocol error";
        else if (code == LIBSSH2_ERROR_EAGAIN)
            msg = "operation would block";
        else if (code == LIBSSH2_ERROR_BUFFER_TOO_SMALL)
            msg = "buffer too small";
        else if (code == LIBSSH2_ERROR_BAD_USE)
            msg = "bad use error";
        else if (code == LIBSSH2_ERROR_COMPRESS)
            msg = "compression error";
        else if (code == LIBSSH2_ERROR_OUT_OF_BOUNDARY)
            msg = "out of bounds";
        else if (code == LIBSSH2_ERROR_AGENT_PROTOCOL)
            msg = "invalid agent protocol";
        else if (code == LIBSSH2_ERROR_SOCKET_RECV)
            msg = "error receiving on socket";
        else if (code == LIBSSH2_ERROR_ENCRYPT)
            msg = "bad encrypt";
        else if (code == LIBSSH2_ERROR_BAD_SOCKET)
            msg = "bad socket";
        else if (code == LIBSSH2_ERROR_KNOWN_HOSTS)
            msg = "known hosts error";
        else if (code ==LIBSSH2_FX_EOF)
            msg = "end of file";
        else if (code ==LIBSSH2_FX_NO_SUCH_FILE)
            msg = "no such file";
        else if (code ==LIBSSH2_FX_PERMISSION_DENIED)
            msg = "permission denied";
        else if (code ==LIBSSH2_FX_FAILURE)
            msg = "failure";
        else if (code ==LIBSSH2_FX_BAD_MESSAGE)
            msg = "bad message";
        else if (code ==LIBSSH2_FX_NO_CONNECTION)
            msg = "no connection";
        else if (code ==LIBSSH2_FX_CONNECTION_LOST)
            msg = "connection lost";
        else if (code ==LIBSSH2_FX_OP_UNSUPPORTED)
            msg = "operation unsupported";
        else if (code ==LIBSSH2_FX_INVALID_HANDLE)
            msg = "invalid handle";
        else if (code ==LIBSSH2_FX_NO_SUCH_PATH)
            msg = "no such path";
        else if (code ==LIBSSH2_FX_FILE_ALREADY_EXISTS)
            msg = "file already exists";
        else if (code ==LIBSSH2_FX_WRITE_PROTECT)
            msg = "file is write protected";
        else if (code ==LIBSSH2_FX_NO_MEDIA)
            msg = "no media available";
        else if (code ==LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM)
            msg = "no space on filesystem";
        else if (code ==LIBSSH2_FX_QUOTA_EXCEEDED)
            msg = "quota exceeded";
        else if (code ==LIBSSH2_FX_UNKNOWN_PRINCIPAL)
            msg = "unknown principal";
        else if (code ==LIBSSH2_FX_LOCK_CONFLICT)
            msg = "lock conflict";
        else if (code ==LIBSSH2_FX_DIR_NOT_EMPTY)
            msg = "directory not empty";
        else if (code ==LIBSSH2_FX_NOT_A_DIRECTORY)
            msg = "not a directory";
        else if (code ==LIBSSH2_FX_INVALID_FILENAME)
            msg = "invalid filename";
        else if (code ==LIBSSH2_FX_LINK_LOOP)
            msg = "link loop";
        else
            msg = "unknown error";
        super(msg, file, line, next);
    }
}
