#ifndef SERVERSTATE_H
#define SERVERSTATE_H

#include <vector>

#include "tox/tox.h"

class ServerState
{
public:
    ServerState();

    struct Friend {
        uint8_t *name;
        uint8_t *statusMessage;
        bool connected;
    };

    Friend *selfState = new Friend;
    std::vector<Friend *> *friendList = new std::vector<Friend *>;

};

#endif // SERVERSTATE_H
