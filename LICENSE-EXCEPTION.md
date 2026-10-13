# FR_OS plugin exception

Additional permission under section 7 of the GNU Affero General Public
License, version 3 ("AGPLv3").

FR_OS is licensed under the AGPLv3 (see [LICENSE](LICENSE)). As an
additional permission, the copyright holders of FR_OS grant you the
following.

## Definitions

- **"FR_OS"** means the software in this repository, and any version of it
  conveyed under the AGPLv3 with this exception attached.
- **"Plugin Interface"** means the documented mechanism by which FR_OS
  discovers and loads separately distributed Python packages at run time:
  the Python entry-point groups whose names begin with `frfw.`, and the
  objects FR_OS hands to a package it loads through them.
- **"Plugin"** means a work that is not derived from FR_OS other than by
  interacting with it through the Plugin Interface, that is distributed as
  a separate package, and that is loaded by FR_OS only at run time through
  the Plugin Interface.

## Permission

You may combine FR_OS with a Plugin, and convey or make available over a
network the resulting combination, without the terms of the AGPLv3
applying to the Plugin itself. You may convey the Plugin under terms of
your choice, provided that:

1. FR_OS itself, including any modification you make to it, remains under
   the AGPLv3 with this exception, and you comply with the AGPLv3 for it
   (including section 13 when users interact with it over a network); and
2. the Plugin does not copy or modify FR_OS's source code, other than the
   names and signatures the Plugin Interface requires.

## Scope

This permission covers only the Plugin. It does not permit removing or
weakening any other term of the AGPLv3 for FR_OS. If you modify FR_OS, you
may extend this exception to your version, but you are not obliged to; if
you do not, delete this file from your version.
