#pragma once

// Cross-platform entry point.  Invoked by the platform-specific main()
// in posix.cpp / win32.cpp after argv has been transcoded to UTF-8.
int aas_sign_main(int argc, char **argv);

