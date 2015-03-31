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
    bool connected = false;
    std::string redirectionPubKey;
    int32_t redirectionFriendNumber = -1;

    std::string byteToHex(const uint8_t *data, uint16_t length);
    bool hexToByte(const std::string hexString, uint8_t* data, uint16_t length);
    int hexCharToInt(char input);

    void selfConnectionStatusChanged(TOX_CONNECTION connectionStatus);
    void friendRequestReceived(const uint8_t *publicKey);
    void friendMessageReceived(int32_t friendNumber, TOX_MESSAGE_TYPE type, const uint8_t * message, uint16_t messageLength);

    static void callbackSelfConnectionStatus(Tox *tox, TOX_CONNECTION connection_status, void *user_data);
    static void callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data);
    static void callbackFriendMessageReceived(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data);

    void writeToLog(const std::string &text);

    std::string getDataDir();
    void saveTox();
    bool loadTox(const uint8_t *data, size_t fileSize);
    size_t loadToxFileSize();
    void saveConfig();
    void loadConfig();
};

#endif // SERVER_H
