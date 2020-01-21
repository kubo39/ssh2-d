module ssh2;

public import ssh2.session;

shared static this()
{
    version (Posix)
    {
        import ssh2.ffi;
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
