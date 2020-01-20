import ssh2.session;

void smokeSession()
{
    import core.time : msecs;

    auto sess = new Session();
    sess.banner("foo");
    assert(sess.blocking);
    assert(sess.timeout == 0.msecs);
    sess.compress(true);
    assert(sess.hostKey() == HostKey.init);
    sess.methodPref(MethodType.KEX, "diffie-hellman-group14-sha1");
    assert(sess.methods(MethodType.KEX) is null);
    sess.blocking(true);
    sess.timeout(0.msecs);
}

void main()
{
    // Session.
    smokeSession();
}
