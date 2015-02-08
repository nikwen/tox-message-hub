#ifndef SERVER_H
#define SERVER_H

#include <string>

#include "tox/tox.h"

class Server
{
public:
    Server();

    void startLoop();

private:
    Tox *tox;
//    std::string redirectionPubKey; //TODO: Why does network connectivity stop working when we uncomment this?

    std::string byteToHex(const uint8_t *data, uint16_t length);

    void friendRequestReceived(const uint8_t *public_key);
    void friendMessageReceived(int32_t friendnumber, const uint8_t * message, uint16_t length);

    static void callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata);
    static void callbackFriendMessageReceived(Tox *tox, int32_t friendnumber, const uint8_t * message, uint16_t length, void *userdata);

    void writeToLog(const std::string &text);

    void saveTox();
    bool loadTox();
};

#endif // SERVER_H
