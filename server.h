#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <map>
#include <queue>
#include <vector>

#include "tox/tox.h"
#include "serverstate.h"

class Server
{
public:
    Server();

    void startLoop();

private:
    enum FriendUpdateMode {
        SEND_NORMAL,
        ONLY_CHANGES,
        FRIENDLIST_ITEM,
        FRIENDLIST_END
    };

    Tox *tox = nullptr;
    bool connected = false;
    std::string redirectionPubKey;
    uint32_t redirectionFriendNumber = UINT32_MAX;
    bool writeLogToCout = false;

    std::vector<std::string> friendRequestPublicKeyList;

    std::map<uint32_t, std::queue<std::string>*> messageQueueMap;
    ServerState *redirectionServerState = new ServerState;

    std::string byteToHex(const uint8_t *data, uint16_t length);
    bool hexToByte(const std::string hexString, uint8_t* data, uint16_t length);
    int hexCharToInt(char input);
    std::string intToString(int value, int digits);

    void sendPendingFriendRequestList();
    void sendFriendList();
    bool sendFriendUpdate(uint32_t friendNumber, FriendUpdateMode mode = SEND_NORMAL);

    void sendMessageWithQueue(Tox *tox, uint32_t friendNumber, TOX_MESSAGE_TYPE messageType, uint8_t *message, size_t messageLength, TOX_ERR_FRIEND_SEND_MESSAGE *error);

    void selfConnectionStatusChanged(TOX_CONNECTION connectionStatus);
    void friendRequestReceived(const uint8_t *publicKey);
    void friendMessageReceived(int32_t friendNumber, TOX_MESSAGE_TYPE type, const uint8_t * message, size_t messageLength);
    void friendConnectionStatusChanged(Tox *tox, uint32_t friendNumber, TOX_CONNECTION connectionStatus);
    void friendNameChanged(Tox *tox, uint32_t friendNumber, const uint8_t *name, size_t length);
    void friendStatusMessageChanged(Tox *tox, uint32_t friendNumber, const uint8_t *message, size_t length);
    void friendStatusChanged(Tox *tox, uint32_t friendNumber, TOX_USER_STATUS status);

    static void callbackSelfConnectionStatus(Tox *tox, TOX_CONNECTION connection_status, void *user_data);
    static void callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data);
    static void callbackFriendMessageReceived(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data);
    static void callbackFriendConnectionStatus(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data);
    static void callbackFriendName(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data);
    static void callbackFriendStatusMessage(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, void *user_data);
    static void callbackFriendStatus(Tox *tox, uint32_t friend_number, TOX_USER_STATUS status, void *user_data);

    void writeToLog(const std::string &text);

    std::string getDataDir();
    void saveTox();
    bool loadTox(const uint8_t *data, size_t fileSize);
    size_t loadToxFileSize();
    void saveConfig();
    void loadConfig();
    void loadGlobalConfig();
};

#endif // SERVER_H
