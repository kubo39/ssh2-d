module ssh2;

public import ssh2.channel;
public import ssh2.session;

version (Posix)
{
    // We only support OpenSSL >= 1.1.0.
    //

    //enum OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000UL;
    extern (C) int OPENSSL_init_ssl(ulong opts, void* settings);
}

shared static this()
{
    version (Posix)
    {
        import ssh2.ffi;

        // Initialize OpenSSL to tell libssh2 not do its own thing as
        // we've already taken care of it.
        //
        // To avoid heap corruption during initialization in OpenSSL 1.1.0,
        // not to use OPENSSL_INIT_LOAD_SSL_STRINGS here.
        // See: https://github.com/openssl/openssl/issues/3505.
        OPENSSL_init_ssl(0, null);
        assert(libssh2_init(LIBSSH2_INIT_NO_CRYPTO) == 0);
    }
    else version (Windows)
    {
        import ssh2.ffi;
        assert(libssh2_init(0) == 0);
    }
    else static assert(false, "Unsupported platform.");
}

shared static ~this()
{
    import ssh2.ffi;
    libssh2_exit();
}
