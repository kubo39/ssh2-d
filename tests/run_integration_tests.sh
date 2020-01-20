#!/usr/bin/env bash
#
# This script is stolen from ssh2-rs and modified slighty.
# Please see https://github.com/alexcrichton/ssh2-rs.

set -ex

export D_SSH2_FIXTURE_PORT=8022

cleanup() {
    # Stop the ssh server and local ssh agent
    kill $(< $SSHDIR/sshd.pid) || true

    test -f $SSHDIR/sshd.log && cat $SSHDIR/sshd.log
}
trap cleanup EXIT

SSHDIR=$(pwd)/tests/sshd

rm -rf $SSHDIR
mkdir -p $SSHDIR

ssh-keygen -t rsa -f $SSHDIR/id_rsa -N "" -q
chmod 0600 $SSHDIR/id_rsa*
cp $SSHDIR/id_rsa.pub $SSHDIR/authorized_keys

ssh-keygen -f $SSHDIR/ssh_host_rsa_key -N '' -t rsa

cat > $SSHDIR/sshd_config <<-EOT
AuthorizedKeysFile=$SSHDIR/authorized_keys
HostKey=$SSHDIR/ssh_host_rsa_key
PidFile=$SSHDIR/sshd.pid
Subsystem sftp internal-sftp
UsePAM yes
X11Forwarding yes
PrintMotd yes
PermitTunnel yes
AllowTcpForwarding yes
MaxStartups 500
# Relax modes when the repo is under eq: /var/tmp
StrictModes no
EOT

cat $SSHDIR/sshd_config

# Start a ssh server
/usr/sbin/sshd -p $D_SSH2_FIXTURE_PORT -f $SSHDIR/sshd_config -E $SSHDIR/sshd.log
# Give it a moment to start up
sleep 2

# Run the tests against it
dub test --main-file tests/runner.d
