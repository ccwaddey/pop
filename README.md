# POP

A POP3 server.

This server is designed to run on OpenBSD. It is event-driven,
privilege-separated, pledg(2)ed and unveil(2)ed and was written with security as the
primary focus. It only supports IPv4 and maildir. It should probably have a
better name ;).

# Usage

tldr: pop is picky; read on.

tldr if you really don't want to read on: there are examples in the repo of how
to do everything. The file formats are picky. You should invoke with something
like: popd -a authtab -u usertab -l ipv4addr -c certificatfile -k
privatekeyfile. You will also need to modify AUTHPOPFILE and WRKRPOPFILE to the
locations of the authpop and wrkrpop binaries respectively. Also read the
(short) sections on "Delivery" and "Creating the _pop3d user".

## User files

pop is designed to work with OpenSMTPD (or at least to make administration
slightly easier with OpenSMTPD) and is designed to support virtual users (so
that you don't have to add a real user to your system for every email
account).

Because OpenSMTPD currently handles virtual users by having a separate table for
authorization and users, pop does too. The authorization file (which does not
have a sane default name) is specified with the -a option and should be given an
absolute path. The format of the file is one username-password hash per line
with no blank lines. A username (which should consist of only lower case letters
and digits) should be put at the start of each line and should be followed by
one or more consecutive space or tab characters. Following the spaces/tabs there
should be an OpenBSD hash of the user's password. This hash can be generated
using the crypt_newhash(3) function and must use the bcrypt algorithm. The line
should end immediately after the hash (a newline character immediately follows
the hash).

The user file has one user per line, with no blank lines. It also does not have
a sane default, and it is specified with the -u option. The file format is as
follows: at the beginning of the line is the username as given in the
authorization file, followed by one or more spaces/tabs; then there should be a
valid uid (user id), followed by a literal ':', a valid gid (group id), and the
maildirstring for that user, followed immediately by the end of the line. The
maildirstring does not have to be the actual maildir for the user; for example,
if each user has their maildir in $HOME/arbitrary_Maildir_directory, the
maildirstring may simply be the user's home directory, as long as you provide
the -e arbitrary_Maildir_directory option at the command line. The uid and gid
should be chosen to provide sufficient privilege to read, create, and modify
files in the user's maildir. For testing, I had a directory testmaildir under my
$HOME directory with directories user0000 to user9999 being the maildirs for
user0000 to user9999 respectively, and the uid and gid were just my personal uid
and gid (1000). The pathname for maildirstring should be absolute.

## Certificates and Keys

pop only supports TLS version 1.3 currently, although if you need to change
this, it would be trivial to modify the source code. The private key is not
currently set up to be password protected. I should probably change that for
those of you who would start up your servers manually, but I haven't done it
yet. Specify the absolute file locations of your certificate and keyfile with
the -c and -k options respectively.

## Listening address

pop only supports IPv4 currently, although I should change this ASAP. Specify
the address that pop should listen on with the -l option, e.g. -l
192.168.0.25. You should give a numerical address, not a hostname.

## Delivery

There are two main issues to cover here. The first is that you should use
testmda.c to deliver the mail with OpenSMTPD. If you would like to get debugging
info change the line with "/home/me/pop/mdainfo" to a file on your system that
will hold the debugging info. You can compile testmda.c with something like:

cc testmda.c -o testmda -lcrypto

Then configure OpenSMTPD to deliver mail using testmda. See smtpd.conf(5). This
mda will work with pop by locking the popcache file (which you'll find in
maildirs serviced by pop) to make pop more efficient and prevent duplicate file
names for messages.

The second thing (which doesn't really relate to delivery but oh well), is that
you should add a "senders file" if you plan on having more than one virtual
user. This is really an OpenSMTPD thing, but if you don't want your virtual
users sending mail as other virtual users, then you should probably read
smtpd.conf(5) and set one of these up.

## Adding the _pop3d user

authpop.c expects there to be a _pop3d user that it can switch to for privilege
dropping. You should add one, and preferably make /var/empty its home dir and
don't allow logins and create a login class that gives it plenty of open file
descriptors to work with.

## Logging

If you want to get logging info, you'll have to set up syslog.conf. I have the following lines appended to my syslog.conf:

!wrkrpop
mail.debug	/var/log/debugmaillog

!authpop
mail.debug	/var/log/debugmaillog

!popd
mail.debug	/var/log/debugmaillog

You also shouldn't add more than ten -v's because you'll get WAY too much info. Leaving it at 0, 1, or 2 -v's will be more than enough.