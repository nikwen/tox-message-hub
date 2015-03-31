#include "server.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <algorithm>

#include "config.h"

using namespace std;

Server::Server() {
    //Determine whether to write the log messages to cout

    loadConfig(true);

    //Create tox object

    Tox_Options *toxOptions = tox_options_new(NULL);

    if (toxOptions == NULL) {
        writeToLog("Failed to create new ToxOptions instance");
        return;
    }

    //Try to load tox object from file

    size_t loadFileSize = loadToxFileSize();

    if (loadFileSize != -1) {
        uint8_t * data = new uint8_t[loadFileSize];

        if (loadTox(data, loadFileSize)) {
            TOX_ERR_NEW *loadingError = new TOX_ERR_NEW;

            tox = tox_new(toxOptions, data, loadFileSize, loadingError);

            if (*loadingError != TOX_ERR_NEW_OK) {
                writeToLog("Saved tox id exists but loading failed");
                writeToLog("Aborting");
                return;
            }

            delete loadingError;
        } else {
            writeToLog("Loading saved tox id failed");
            writeToLog("Aborting");
            return;
        }

        delete [] data;
    } else {
        TOX_ERR_NEW *loadingError = new TOX_ERR_NEW;

        tox = tox_new(toxOptions, NULL, 0, NULL);

        if (*loadingError != TOX_ERR_NEW_OK) {
            writeToLog("Failed to create new tox instance");
            writeToLog("Aborting");
            return;
        }

        //Set default name and status

        tox_self_set_name(tox, (uint8_t *) "Tox bot", 7, NULL);
        tox_self_set_status_message(tox, (uint8_t *) "Replying to your messages", 25, NULL);

        delete loadingError;
    }

    loadConfig(false);

    tox_self_set_status(tox, TOX_USER_STATUS_NONE);

    //Print tox id to the logs

    uint8_t selfAddress[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, selfAddress);

    writeToLog(byteToHex(selfAddress, TOX_ADDRESS_SIZE));

    //Bootstrap

    int bootstrapResult = tox_bootstrap(tox, "192.254.75.102", 33445, new uint8_t[32] {
                                   0x95, 0x1C, 0x88, 0xB7, 0xE7, 0x5C, 0x86, 0x74, 0x18, 0xAC, 0xDB, 0x5D, 0x27, 0x38, 0x21, 0x37,
                                   0x2B, 0xB5, 0xBD, 0x65, 0x27, 0x40, 0xBC, 0xDF, 0x62, 0x3A, 0x4F, 0xA2, 0x93, 0xE7, 0x5D, 0x2F
                                   }, NULL);

    writeToLog("Bootstrap: " + to_string(bootstrapResult));

    //Toxcore callbacks

    tox_callback_self_connection_status(tox, callbackSelfConnectionStatus, this);
    tox_callback_friend_request(tox, callbackFriendRequestReceived, this);
    tox_callback_friend_message(tox, callbackFriendMessageReceived, this);

    saveTox();
}

void Server::startLoop() {
    while (1) {
        tox_iterate(tox);
        usleep(tox_iteration_interval(tox) * 1000);
    }
}

string Server::byteToHex(const uint8_t *data, uint16_t length) {
    char hexString[length * 2];
    static const char hexChars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for(int j = 0; j < length; j++){
        hexString[j*2] = hexChars[((data[j] >> 4) & 0xF)];
        hexString[(j*2) + 1] = hexChars[(data[j]) & 0x0F];
    }

    return string(hexString, length * 2);
}

//Returns true if successful, false if hexString is too short
bool Server::hexToByte(const string hexString, uint8_t* data, uint16_t length) {
    if (hexString.length() / 2 < length) {
        return false;
    }

    for (int i = 0; i < length; i++) {
        data[i] = hexCharToInt(hexString.at(2 * i)) * 16 + hexCharToInt(hexString.at(2 * i + 1));
    }

    return true;
}

int Server::hexCharToInt(char input) {
    if (input >= '0' && input <= '9') {
        return input - '0';
    } else if (input >= 'A' && input <= 'F') {
        return input - 'A' + 10;
    } else if (input >= 'a' && input <= 'f') {
        return input - 'a' + 10;
    } else {
        return -1;
    }
}

void Server::selfConnectionStatusChanged(TOX_CONNECTION connectionStatus) {
    connected = (connectionStatus != TOX_CONNECTION_NONE);
    writeToLog("Connected: " + to_string(connected));
}

void Server::callbackSelfConnectionStatus(Tox *tox, TOX_CONNECTION connectionStatus, void *user_data) {
    static_cast<Server *>(user_data)->selfConnectionStatusChanged(connectionStatus);
}

//Automatically add everyone who adds the bot
void Server::friendRequestReceived(const uint8_t *publicKey) {
    //Add friend back
    uint32_t friendNumber = tox_friend_add_norequest(tox, publicKey, NULL);

    if (friendNumber == UINT32_MAX) {
        writeToLog("Failed to add friend");
        return;
    }

    string publicKeyString = byteToHex(publicKey, TOX_PUBLIC_KEY_SIZE);
    writeToLog(string("Added friend ") + publicKeyString + " (friend number: " + to_string(friendNumber) + ")");

    saveTox();

    //Set friend as redirection target if it is the first one
    if (tox_self_get_friend_list_size(tox) == 1) {
        redirectionPubKey = publicKeyString;
        redirectionFriendNumber = friendNumber;
        writeToLog("Redirecting to: " + redirectionPubKey + ", friend number: " + to_string(redirectionFriendNumber));
        saveConfig();
    }
}

void Server::callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendRequestReceived(public_key);
}

void Server::friendMessageReceived(int32_t friendNumber, TOX_MESSAGE_TYPE type, const uint8_t * message, uint16_t messageLength) { //TODO: Message type
    string messageString((char*) message, messageLength);

    //Only accept commands from redirection target
    if (friendNumber == redirectionFriendNumber && type == TOX_MESSAGE_TYPE_NORMAL && messageString.substr(0, 3) == string("###")) {
        string body = messageString.substr(3);
        if (body.find(" set_name ") == 0 && body.length() > 10) {
            uint16_t uintNameArrayLength = min((int) (body.length() - 10), TOX_MAX_NAME_LENGTH);
            uint8_t *uintNameArray = new uint8_t[uintNameArrayLength];
            memcpy(uintNameArray, message + 13, uintNameArrayLength);

            string name = body.substr(10, uintNameArrayLength);

            if (tox_self_set_name(tox, uintNameArray, uintNameArrayLength, NULL)) {
                writeToLog("Changed name to " + name);
                saveTox();
            } else {
                writeToLog("Changing name to " + name + " failed");
            }

            delete[] uintNameArray;
            return;
        } else if (body.find(" set_status ") == 0 && body.length() > 12) {
            uint16_t uintStatusArrayLength = min((int) (body.length() - 12), TOX_MAX_STATUS_MESSAGE_LENGTH);
            uint8_t *uintStatusArray = new uint8_t[uintStatusArrayLength];
            memcpy(uintStatusArray, message + 15, uintStatusArrayLength);

            string status = body.substr(12, uintStatusArrayLength);

            if (tox_self_set_status_message(tox, uintStatusArray, uintStatusArrayLength, NULL)) {
                writeToLog("Changed status to " + status);
                saveTox();
            } else {
                writeToLog("Changing status to " + status + " failed");
            }

            delete[] uintStatusArray;
            return;
        } else if (body.find(" message ") == 0 && body.length() > 9) {
            string text = body.substr(9);
            int noNumberPos = text.find_first_not_of("0123456789");
            int spacePos = text.find(" ");
            if (spacePos > 0 && noNumberPos == spacePos) {
                uint32_t friendId = atoi(text.substr(0, noNumberPos).c_str());
                if (tox_friend_exists(tox, friendId)) {
                    int sendMessageLength = text.length() - noNumberPos - 1;
                    if (sendMessageLength > 0) {
                        uint16_t uintSendMessageArrayLength = min(sendMessageLength, TOX_MAX_MESSAGE_LENGTH);
                        uint8_t *uintSendMessageArray = new uint8_t[uintSendMessageArrayLength];
                        memcpy(uintSendMessageArray, message + noNumberPos + 13, uintSendMessageArrayLength);

                        string sendMessage = body.substr(noNumberPos + 13, uintSendMessageArrayLength);

                        TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
                        tox_friend_send_message(tox, friendId, TOX_MESSAGE_TYPE_NORMAL, uintSendMessageArray, uintSendMessageArrayLength, sendError);

                        if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                            writeToLog("Sent message \"" + sendMessage + "\"");
                        } else {
                            writeToLog("Sending message \"" + sendMessage + "\" failed");
                        }

                        delete sendError;
                        delete[] uintSendMessageArray;
                        return;
                    } else {
                        writeToLog("No message entered");
                    }
                } else {
                    writeToLog("Given friend ID does not exist");
                }
            } else {
                writeToLog("No friend ID entered");
            }
        } else {
            writeToLog("Could not interpret command");
        }
    }

    size_t nameLength = tox_friend_get_name_size(tox, friendNumber, NULL);

    uint8_t *name = NULL;
    bool success = false;

    if (nameLength != SIZE_MAX) {
        name = new uint8_t[nameLength];
        success = tox_friend_get_name(tox, friendNumber, name, NULL);

        if (!success) {
            writeToLog("Failed to get friend name");
        }
    } else {
        writeToLog("Failed to get friend name size");
    }

    uint8_t *sendMessage = NULL;
    int sendMessageLength = nameLength + messageLength + 2;
    if (nameLength != SIZE_MAX && success && sendMessageLength < TOX_MAX_MESSAGE_LENGTH) {
        sendMessage = new uint8_t[sendMessageLength];
        string divider = ": ";
        memcpy(sendMessage, name, nameLength);
        memcpy(sendMessage + nameLength, divider.c_str(), 2);
        memcpy(sendMessage + nameLength + 2, message, messageLength);
    } else {
        sendMessage = new uint8_t[messageLength];
        memcpy(sendMessage, message, messageLength);
        sendMessageLength = messageLength;
    }

    TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
    tox_friend_send_message(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, sendMessage, sendMessageLength, sendError); //TODO: Handle actions properly

    if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
        writeToLog(string("Redirected message \"") + string((char *) sendMessage, sendMessageLength) + "\"");
    } else {
        writeToLog(string("Redirecting message \"") + string((char *) sendMessage, sendMessageLength) + "\" failed");
    }

    delete sendError;
    delete[] name;
    delete[] sendMessage;
}

void Server::callbackFriendMessageReceived(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendMessageReceived(friend_number, type, message, length);
}

string Server::getDataDir() {
    string dataDirString = string(DATA_DIR);

    //If the data dir contains a tilde, replace it with the user's home directory

    if (DATA_DIR[0] == '~') {
        char *homeDir = getpwuid(getuid())->pw_dir;
        dataDirString = string(homeDir) + dataDirString.substr(1);
    }

    return dataDirString;
}

/*
 * Writes to log file on snappy systems, otherwise to cout
 */
void Server::writeToLog(const string &text) { //TODO: Config switch to use cout instead (for development)
    if (writeLogToCout) {
        cout << text << std::endl;
        return;
    }

    ofstream logfile(getDataDir() + "log_000.txt", ios_base::out | ios_base::app);

    if (logfile) {
        logfile << text << std::endl;
    } else {
        cout << text << std::endl;
        return;
    }

    logfile.close();
}

#define CONFIG_REDIRECTION_PUB_KEY "redirectionPubKey="
#define CONFIG_WRITE_LOG_TO_COUT "writeLogToCout="

void Server::loadConfig(bool onlyToxIndependentValues) { //Parameter: Skip options which do rely on a valid tox object before its creation
    ifstream loadFile(getDataDir() + "profile_000.conf");

    if (!loadFile) {
        writeToLog("Failed to open config file for loading");
        return;
    }

    string line;

    while (getline(loadFile, line)) {
        int pos;
        if (!onlyToxIndependentValues && (pos = line.find(CONFIG_REDIRECTION_PUB_KEY)) == 0) {
            string pubKey = line.substr(18); //CONF_REDIRECTION_PUB_KEY.length()
            if (pubKey.length() == TOX_PUBLIC_KEY_SIZE * 2) {
                uint8_t *pubKeyArray = new uint8_t[TOX_PUBLIC_KEY_SIZE];

                hexToByte(pubKey, pubKeyArray, TOX_PUBLIC_KEY_SIZE);

                uint32_t friendNumber = tox_friend_by_public_key(tox, pubKeyArray, NULL);
                if (friendNumber != UINT32_MAX) { //TODO: What if added before program started?
                    redirectionPubKey = pubKey;
                    redirectionFriendNumber = friendNumber;
                    writeToLog("redirectionPubKey: " + redirectionPubKey);
                    writeToLog("redirectionFriendNumber: " + to_string(redirectionFriendNumber));
                } else {
                    writeToLog("Given redirectionPubKey does not belong to a friend");
                }

                delete[] pubKeyArray;
            } else {
                writeToLog("Given redirectionPubKey has wrong length: " + to_string(pubKey.length()));
            }
        } else if ((pos = line.find(CONFIG_WRITE_LOG_TO_COUT)) == 0) {
            string value = line.substr(15); //CONFIG_WRITE_LOG_TO_COUT.length()
            std::transform(value.begin(), value.end(), value.begin(), ::tolower); //toLower()
            writeLogToCout = (value == "true");
        }
    }

    loadFile.close();

    writeToLog("Loaded config");
}

void Server::saveConfig() {
    ofstream saveFile(getDataDir() + "profile_000.conf");

    if (!saveFile) {
        writeToLog("Failed to open config file for saving");
        return;
    }

    if (!redirectionPubKey.empty()) {
        saveFile << CONFIG_REDIRECTION_PUB_KEY << redirectionPubKey << endl;
    }
    if (writeLogToCout) {
        saveFile << CONFIG_WRITE_LOG_TO_COUT << to_string(writeLogToCout) << endl;
    }

    saveFile.close();
}

size_t Server::loadToxFileSize() {
    ifstream loadFile(getDataDir() + "profile_000.tox", ios_base::in | ios_base::binary);

    if (!loadFile) {
        writeToLog("Failed to open tox id file for loading");
        return -1;
    }

    loadFile.seekg(0, ios::end);
    size_t fileSize = loadFile.tellg();

    loadFile.close();

    return fileSize;
}

bool Server::loadTox(const uint8_t *data, size_t fileSize) {
    ifstream loadFile(getDataDir() + "profile_000.tox", ios_base::in | ios_base::binary);

    if (!loadFile) {
        writeToLog("Failed to open tox id file for loading");
        return false;
    }

    loadFile.read((char *) data, fileSize);
    loadFile.close();

    writeToLog("Loaded tox from tox id file");

    return true;
}

void Server::saveTox() {
    ofstream saveFile(getDataDir() + "profile_000.tox", ios_base::out | ios_base::binary);

    if (!saveFile) {
        writeToLog("Failed to open tox id file for saving");
        return;
    }

    size_t fileSize = tox_get_savedata_size(tox);

    uint8_t *data = new uint8_t[fileSize];
    tox_get_savedata(tox, data);

    saveFile.write((char *) data, fileSize);

    saveFile.close();

    delete[] data;

    writeToLog("Saved tox status");
}
