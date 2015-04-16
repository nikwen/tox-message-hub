#ifndef SERVERSTATE_H
#define SERVERSTATE_H

#include <map>

#include "tox/tox.h"

class ServerState
{
public:
    ServerState();

    struct Friend {
        uint8_t *name = nullptr;
        uint8_t *statusMessage = nullptr;
        bool connected = false;
    };

    Friend *selfState = new Friend;
    std::map<uint32_t, Friend*> friendMap;

};

#endif // SERVERSTATE_H
