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
    Tox *tox = nullptr;
    std::string redirectionPubKey;
    int32_t redirectionFriendNumber = -1;

    std::string byteToHex(const uint8_t *data, uint16_t length);
    bool hexToByte(const std::string hexString, uint8_t* data, uint16_t length);
    int hexCharToInt(char input);

    void friendRequestReceived(const uint8_t *public_key);
    void friendMessageReceived(int32_t friendnumber, const uint8_t * message, uint16_t messageLength);

    static void callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata);
    static void callbackFriendMessageReceived(Tox *tox, int32_t friendnumber, const uint8_t * message, uint16_t length, void *userdata);

    void writeToLog(const std::string &text);

    void saveTox();
    bool loadTox();
    void saveConfig();
    void loadConfig();
};

#endif // SERVER_H
