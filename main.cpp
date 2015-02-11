#include "server.h"

#include <unistd.h>

int main()
{
    //Wait one second before starting the server to make sure that we
    //have write access to the required directories on Snappy Ubuntu Core
    //when the service is started directly after installing the package
    //for the first time.
    usleep(1000000);

    //Start server
    Server *s = new Server();
    s->startLoop();

    return 0;
}

