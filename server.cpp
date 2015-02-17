#include "server.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <unistd.h>

#include "config.h"

using namespace std;

Server::Server() {
    //Create tox object

    Tox_Options toxOptions;
    toxOptions.proxy_type = TOX_PROXY_NONE;
    toxOptions.proxy_address[0] = 0;
    toxOptions.proxy_port = 0;

    tox = tox_new(&toxOptions);

    if (tox == NULL) {
        writeToLog("toxcore failed to start");
        return;
    }

    //Load tox status or set default identity information

    if (!loadTox()) {
        tox_set_name(tox, (uint8_t *) "Tox bot", 7);
        tox_set_status_message(tox, (uint8_t *) "Replying to your messages", 25);
    }

    loadConfig();

    tox_set_user_status(tox, TOX_USERSTATUS_NONE);

    //Print tox id to the logs

    uint8_t friendAddress[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox, friendAddress);

    writeToLog(byteToHex(friendAddress, TOX_FRIEND_ADDRESS_SIZE));

    //Bootstrap

    int bootstrapResult = tox_bootstrap_from_address(tox, "192.254.75.102", 33445, new uint8_t[32] {
                                   0x95, 0x1C, 0x88, 0xB7, 0xE7, 0x5C, 0x86, 0x74, 0x18, 0xAC, 0xDB, 0x5D, 0x27, 0x38, 0x21, 0x37,
                                   0x2B, 0xB5, 0xBD, 0x65, 0x27, 0x40, 0xBC, 0xDF, 0x62, 0x3A, 0x4F, 0xA2, 0x93, 0xE7, 0x5D, 0x2F
                                   });

    writeToLog("Bootstrap: " + to_string(bootstrapResult));

    //Toxcore callbacks

    tox_callback_friend_request(tox, callbackFriendRequestReceived, this);
    tox_callback_friend_message(tox, callbackFriendMessageReceived, this);

    saveTox();
}

void Server::startLoop() {
    int connected = tox_isconnected(tox);
    writeToLog("Connected: " + std::to_string(connected));

    while (1) {
        tox_do(tox);

        if (connected != tox_isconnected(tox)) {
            connected = tox_isconnected(tox);
            writeToLog("Connected: " + to_string(connected));
        }

        usleep(tox_do_interval(tox));
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

//Automatically add everyone who adds the bot
void Server::friendRequestReceived(const uint8_t *public_key) {
    //Add friend back
    int32_t friendNumber = tox_add_friend_norequest(tox, public_key);
    if (friendNumber == -1) {
        writeToLog("Failed to add friend");
        return;
    }

    string publicKey = byteToHex(public_key, TOX_PUBLIC_KEY_SIZE);
    writeToLog(string("Added friend ") + publicKey + " (friend number: " + to_string(friendNumber) + ")");

    saveTox();

    //Set friend as redirection target if it is the first one
    if (tox_count_friendlist(tox) == 1) { //TODO: Save in and load from file
        redirectionPubKey = publicKey;
        redirectionFriendNumber = friendNumber;
        writeToLog("Redirecting to: " + redirectionPubKey + ", friend number: " + to_string(redirectionFriendNumber));
        saveConfig();
    }
}

void Server::callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata) {
    static_cast<Server *>(userdata)->friendRequestReceived(public_key);
}

//Simply reply to all messages by sending back the same one
void Server::friendMessageReceived(int32_t friendnumber, const uint8_t * message, uint16_t messageLength) {
    string messageString((char*) message, messageLength);

    //Only accept commands from redirection target
    if (friendnumber == redirectionFriendNumber && messageString.substr(0, 3) == string("###")) {
        string body = messageString.substr(3);
        if (body.find(" set_name ") == 0 && body.length() > 10) {
            uint16_t uintNameArrayLength = min((int) (body.length() - 10), TOX_MAX_NAME_LENGTH);
            uint8_t *uintNameArray = new uint8_t[uintNameArrayLength];
            memcpy(uintNameArray, message + 13, uintNameArrayLength);

            string name = body.substr(10, uintNameArrayLength);

            if (tox_set_name(tox, uintNameArray, uintNameArrayLength) == 0) {
                writeToLog("Changed name to " + name);
                saveTox();
            } else {
                writeToLog("Changing name to " + name + " failed");
            }

            delete[] uintNameArray;
            return;
        } else if (body.find(" set_status ") == 0 && body.length() > 12) {
            uint16_t uintStatusArrayLength = min((int) (body.length() - 12), TOX_MAX_STATUSMESSAGE_LENGTH);
            uint8_t *uintStatusArray = new uint8_t[uintStatusArrayLength];
            memcpy(uintStatusArray, message + 15, uintStatusArrayLength);

            string status = body.substr(12, uintStatusArrayLength);

            if (tox_set_status_message(tox, uintStatusArray, uintStatusArrayLength) == 0) {
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

                        if (tox_send_message(tox, friendId, uintSendMessageArray, uintSendMessageArrayLength) == 0) {
                            writeToLog("Changed status to " + sendMessage);
                            saveTox();
                        } else {
                            writeToLog("Changing status to " + sendMessage + " failed");
                        }

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

    uint8_t *name = new uint8_t[TOX_MAX_NAME_LENGTH];
    int nameLength = tox_get_name(tox, friendnumber, name);
    int sendMessageLength = nameLength + messageLength + 2;
    int result;
    if (nameLength != -1 && sendMessageLength < TOX_MAX_MESSAGE_LENGTH) {
        uint8_t *sendMessage = new uint8_t[sendMessageLength];
        string divider = ": ";
        memcpy(sendMessage, name, nameLength);
        memcpy(sendMessage + nameLength, divider.c_str(), 2);
        memcpy(sendMessage + nameLength + 2, message, messageLength);

        result = tox_send_message(tox, redirectionFriendNumber, sendMessage, sendMessageLength);

        delete[] sendMessage;
    } else {
        result = tox_send_message(tox, redirectionFriendNumber, message, messageLength);
    }
    delete[] name;

    if (result == 0) {
        writeToLog("Failed to forward message");
    } else {
        writeToLog("Forwarded message");
    }
}

void Server::callbackFriendMessageReceived(Tox *tox, int32_t friendnumber, const uint8_t * message, uint16_t length, void *userdata) {
    static_cast<Server *>(userdata)->friendMessageReceived(friendnumber, message, length);
}

/*
 * Writes to log file on snappy systems, otherwise to cout
 */
void Server::writeToLog(const string &text) {
    ofstream logfile(string(DATA_DIR) + "log_000.txt", ios_base::out | ios_base::app);

    if (logfile) {
        logfile << text << std::endl;
    } else {
        cout << text << std::endl;
        return;
    }

    logfile.close();
}

#define CONFIG_REDIRECTION_PUB_KEY "redirectionPubKey="

void Server::loadConfig() {
    ifstream loadFile(string(DATA_DIR) + "profile_000.conf");

    if (!loadFile) {
        writeToLog("Failed to open config file for loading");
        return;
    }

    string line;

    while (getline(loadFile, line)) {
        int pos;
        if ((pos = line.find(CONFIG_REDIRECTION_PUB_KEY)) == 0) {
            string pubKey = line.substr(18); //CONF_REDIRECTION_PUB_KEY.length()
            if (pubKey.length() == TOX_PUBLIC_KEY_SIZE * 2) {
                uint8_t *pubKeyArray = new uint8_t[TOX_PUBLIC_KEY_SIZE];

                hexToByte(pubKey, pubKeyArray, TOX_PUBLIC_KEY_SIZE);

                int friendNumber = tox_get_friend_number(tox, pubKeyArray);
                if (friendNumber != -1) { //TODO: What if added before program started?
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
        } else {
            writeToLog("Could not interpret line");
        }
    }

    loadFile.close();
}

void Server::saveConfig() {
    ofstream saveFile(string(DATA_DIR) + "profile_000.conf");

    if (!saveFile) {
        writeToLog("Failed to open config file for saving");
        return;
    }

    if (!redirectionPubKey.empty()) {
        saveFile << CONFIG_REDIRECTION_PUB_KEY << redirectionPubKey << endl;
    }

    saveFile.close();
}

bool Server::loadTox() {
    ifstream loadFile(string(DATA_DIR) + "profile_000.tox", ios_base::in | ios_base::binary);

    if (!loadFile) {
        writeToLog("Failed to open tox id file for loading");
        return false;
    }

    loadFile.seekg(0, ios::end);
    size_t fileSize = loadFile.tellg();
    loadFile.seekg(0, ios::beg);

    uint8_t *data = new uint8_t[fileSize];
    loadFile.read((char *) data, fileSize);
    loadFile.close();

    int loadResult = tox_load(tox, data, fileSize);

    delete[] data;
    loadFile.close();

    if (loadResult == 0) {
        writeToLog("Loaded tox status");
        return true;
    } else {
        writeToLog("Failed to load tox status");
        return false;
    }
}

void Server::saveTox() {
    ofstream saveFile(string(DATA_DIR) + "profile_000.tox", ios_base::out | ios_base::binary);

    if (!saveFile) {
        writeToLog("Failed to open tox id file for saving");
        return;
    }

    uint32_t fileSize = tox_size(tox);
    if (fileSize > 0 && fileSize <= INT32_MAX) {
        uint8_t *data = new uint8_t[fileSize];
        tox_save(tox, data);

        saveFile.write((char *) data, fileSize);

        delete[] data;
        writeToLog("Saved tox status");
    } else {
        writeToLog("Invalid fileSize for tox status");
    }

    saveFile.close();
}
