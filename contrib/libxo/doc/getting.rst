
.. index:: Getting libxo

Getting libxo
=============

libxo now ships as part of the FreeBSD Operating System (as of Release
11).

libxo source code lives on github:

  https://github.com/Juniper/libxo

The latest release of libxo is available at:

  https://github.com/Juniper/libxo/releases

We're using `Semantic Versioning`_ to number our releases.  libxo is
open source, distributed under the BSD license.  We follow the
branching scheme from `A Successful Git Branching Model`_:
we do development under the "*develop*" branch, and release from
the "*master*" branch.  To clone a developer tree, run the following
command::

  git clone https://github.com/Juniper/libxo.git -b develop

.. _Semantic Versioning: http://semver.org/spec/v2.0.0.html
.. _A Successful Git Branching Model:
    http://nvie.com/posts/a-successful-git-branching-model

Issues, problems, and bugs should be directly to the issues page on
our github site.

Downloading libxo Source Code
-----------------------------

You can retrieve the source for libxo in two ways:

A. Use a "distfile" for a specific release.  We use github to maintain
   our releases.  Visit the `release page`_ to see the list of
   releases.  To download the latest, look for the release witeh the
   green "Latest release" button and the green "libxo-RELEASE.tar.gz"
   button under that section.

.. _release page: https://github.com/Juniper/libxo/releases

   After downloading that release's distfile, untar it as follows::

       tar -zxf libxo-RELEASE.tar.gz
       cd libxo-RELEASE

   .. admonition:: Solaris Users

     Note: for Solaris users, your "`tar`" command lacks the "-z" flag,
     so you'll need to substitute "`gzip -dc $file | tar xf -`" instead
     of "`tar -zxf $file`".

B. Use the current build from github.  This gives you the most recent
   source code, which might be less stable than a specific release.  To
   build libxo from the git repo::

       git clone https://github.com/Juniper/libxo.git
       cd libxo

   .. admonition:: Be Aware

     The github repository does **not** contain the files generated by
     "*autoreconf*", with the notable exception of the "*m4*" directory.
     Since these files (depcomp, configure, missing, install-sh, etc) are
     generated files, we keep them out of the source code repository.

     This means that if you download the a release distfile, these files
     will be ready and you'll just need to run "configure", but if you
     download the source code from svn, then you'll need to run
     "*autoreconf*" by hand.  This step is done for you by the "*setup.sh*"
     script, described in the next section.

.. _building:

Building libxo
--------------

To build libxo, you'll need to set up the build, run the "*configure*"
script, run the "*make*" command, and run the regression tests.

The following is a summary of the commands needed.  These commands are
explained in detail in the rest of this section::

    sh bin/setup.sh
    cd build
    ../configure
    make
    make test
    sudo make install

The following sections will walk through each of these steps with
additional details and options, but the above directions should be all
that's needed.

Setting up the build
~~~~~~~~~~~~~~~~~~~~

.. admonition: Note

   If you downloaded a distfile, you can skip this step.

Run the "*setup.sh*" script to set up the build.  This script runs the
"*autoreconf*" command to generate the "*configure*" script and other
generated files::

    sh bin/setup.sh

Note: We're are currently using autoreconf version 2.69.

Running the "configure" Script
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure (and autoconf in general) provides a means of building
software in diverse environments.  Our configure script supports
a set of options that can be used to adjust to your operating
environment. Use "`configure --help`" to view these options.

We use the "*build*" directory to keep object files and generated files
away from the source tree.

To run the configure script, change into the "*build*" directory, and
run the "*configure*" script.  Add any required options to the
"`../configure`" command line::

    cd build
    ../configure

Expect to see the "*configure*" script generate the following error::

    /usr/bin/rm: cannot remove `libtoolT': No such file or directory

This error is harmless and can be safely ignored.

By default, libxo installs architecture-independent files, including
extension library files, in the /usr/local directories. To specify an
installation prefix other than /usr/local for all installation files,
include the --prefix=prefix option and specify an alternate
location. To install just the extension library files in a different,
user-defined location, include the "*--with-extensions-dir=dir*" option
and specify the location where the extension libraries will live::

    cd build
    ../configure [OPTION]... [VAR=VALUE]...

Running the "make" Command
++++++++++++++++++++++++++

Once the "*configure*" script is run, build the images using the
"`make`" command::

    make

Running the Regression Tests
++++++++++++++++++++++++++++

libxo includes a set of regression tests that can be run to ensure
the software is working properly.  These test are optional, but will
help determine if there are any issues running libxo on your
machine.  To run the regression tests::

    make test

Installing libxo
~~~~~~~~~~~~~~~~

Once the software is built, you'll need to install libxo using the
"`make install`" command.  If you are the root user, or the owner of
the installation directory, simply issue the command::

    make install

If you are not the "*root*" user and are using the "*sudo*" package, use::

    sudo make install

Verify the installation by viewing the output of "`xo --version`"::

    % xo --version
    libxo version 0.3.5-git-develop
    xo version 0.3.5-git-develop
