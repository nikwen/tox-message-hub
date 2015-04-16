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
        size_t nameSize = 0;
        uint8_t *statusMessage = nullptr;
        size_t statusMessageSize = 0;
        bool connected = false;
    };

    Friend *selfState = new Friend;
    std::map<uint32_t, Friend*> friendMap;

};

#endif // SERVERSTATE_H
