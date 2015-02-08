#include "server.h"

int main()
{
    Server *s = new Server();
    s->startLoop();

    return 0;
}

