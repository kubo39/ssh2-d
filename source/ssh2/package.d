module ssh2;

public import ssh2.session;

shared static this()
{
    version (Posix)
    {
        import ssh2.ffi;
        assert(libssh2_init(LIBSSH2_INIT_NO_CRYPTO) == 0);
    }
    else static assert(false, "Unsupported platform.");
}

shared static ~this()
{
    version (Posix)
    {
        import ssh2.ffi;
        libssh2_exit();
    }
    else static assert(false, "Unsupported platform.");
}
