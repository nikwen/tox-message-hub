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

/*
 * Message prefixes:
 *
 * 10: Friend status update
 * 20: Redirected normal message
 * 21: Redirected action message
 * 30: Friend list item (no explicit start item needed)
 * 31: Friend list end
 * 32: Empty friend list
 * 33: Friend request list item
 * 34: Friend request list end
 * 35: Empty friend request list
 *
 */

Server::Server() {
    //Determine whether to write the log messages to cout

    loadGlobalConfig();

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

        tox = tox_new(toxOptions, NULL, 0, loadingError);

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

    loadConfig();

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
    tox_callback_friend_connection_status(tox, callbackFriendConnectionStatus, this);
    tox_callback_friend_name(tox, callbackFriendName, this);
    tox_callback_friend_status_message(tox, callbackFriendStatusMessage, this);
    tox_callback_friend_status(tox, callbackFriendStatus, this);

    saveTox();
}

void Server::startLoop() {
    while (1) {
        tox_iterate(tox);
        usleep(tox_iteration_interval(tox) * 1000);
    }
}

string Server::byteToHex(const uint8_t *data, uint16_t length) {
    //If we ever decide to use upper case letters here, make sure to change all tolower transforms to toupper transforms!

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

void Server::friendRequestReceived(const uint8_t *publicKey) {

    //Add first friend automatically as redirection target
    //Further friend requests will be forwarded to the redirection target

    if (tox_self_get_friend_list_size(tox) == 0) {

        //Add friend back
        redirectionFriendNumber = tox_friend_add_norequest(tox, publicKey, NULL);

        if (redirectionFriendNumber == UINT32_MAX) {
            writeToLog("Failed to add redirection target friend");
            return;
        }

        saveTox();

        //Set friend as redirection target if it is the first one

        redirectionPubKey = byteToHex(publicKey, TOX_PUBLIC_KEY_SIZE);

        writeToLog("Redirecting to: " + redirectionPubKey + ", friend number: " + to_string(redirectionFriendNumber));
        saveConfig();
    } else {
        string publicKeyString = byteToHex(publicKey, TOX_PUBLIC_KEY_SIZE);

        friendRequestPublicKeyList.push_back(publicKeyString);

        size_t messageLength = 28 + TOX_PUBLIC_KEY_SIZE * 2;

        uint8_t *message = new uint8_t[messageLength];
        memcpy(message, "Pending friend request from ", 28);
        memcpy(message + 28, publicKeyString.c_str(), TOX_PUBLIC_KEY_SIZE * 2);

        TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
        sendMessageWithQueue(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, message, messageLength, sendError);

        if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            writeToLog("Sent update: Pending friend request from " + publicKeyString);
        } else {
            writeToLog("Sending update failed: Pending friend request from " + publicKeyString);
        }

        delete sendError;
        delete[] message;
    }
}

void Server::callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendRequestReceived(public_key);
}

void Server::friendMessageReceived(int32_t friendNumber, TOX_MESSAGE_TYPE type, const uint8_t * message, size_t messageLength) {
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
        } else if (body.find(" set_status_message ") == 0 && body.length() > 20) {
            uint16_t uintStatusArrayLength = min((int) (body.length() - 20), TOX_MAX_STATUS_MESSAGE_LENGTH);
            uint8_t *uintStatusArray = new uint8_t[uintStatusArrayLength];
            memcpy(uintStatusArray, message + 23, uintStatusArrayLength);

            string status = body.substr(20, uintStatusArrayLength);

            if (tox_self_set_status_message(tox, uintStatusArray, uintStatusArrayLength, NULL)) {
                writeToLog("Changed status message to " + status);
                saveTox();
            } else {
                writeToLog("Changing status message to " + status + " failed");
            }

            delete[] uintStatusArray;
            return;
        } else if (body.find(" set_status ") == 0 && body.length() > 12) {
            string text = body.substr(12);
            if (text == "busy") {
                tox_self_set_status(tox, TOX_USER_STATUS_BUSY);
                writeToLog("Changed status to busy");
            } else if (text == "away") {
                tox_self_set_status(tox, TOX_USER_STATUS_AWAY);
                writeToLog("Changed status to away");
            } else if (text == "online") {
                tox_self_set_status(tox, TOX_USER_STATUS_NONE);
                writeToLog("Changed status to online");
            } else {
                writeToLog ("Changing status command couldn't be interpreted.");
            }
            saveTox();
            return;
        } else if (body.find(" message ") == 0 && body.length() > 9) {
            string text = body.substr(9);
            int noNumberPos = text.find_first_not_of("0123456789");
            int spacePos = text.find(" ");
            if (spacePos > 0 && noNumberPos == spacePos) {
                uint32_t friendId = atoi(text.substr(0, noNumberPos).c_str()); //TODO: stoul (also supports finding out noNumberPos!)
                if (tox_friend_exists(tox, friendId)) {
                    int sendMessageLength = text.length() - noNumberPos - 1;
                    if (sendMessageLength > 0) {
                        uint16_t uintSendMessageArrayLength = min(sendMessageLength, TOX_MAX_MESSAGE_LENGTH);
                        uint8_t *uintSendMessageArray = new uint8_t[uintSendMessageArrayLength];
                        memcpy(uintSendMessageArray, message + noNumberPos + 13, uintSendMessageArrayLength);

                        string sendMessage = body.substr(noNumberPos + 10, uintSendMessageArrayLength);

                        TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
                        sendMessageWithQueue(tox, friendId, TOX_MESSAGE_TYPE_NORMAL, uintSendMessageArray, uintSendMessageArrayLength, sendError);

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
        } else if (body == " friendlist") {
            sendFriendList();
            return;
        } else if (body == " pending_fr") {
            sendPendingFriendRequestList();
            return;
        } else if (body.find(" accept_fr ") == 0 && body.length() > 11) {
            if (body.length() == 11 + TOX_PUBLIC_KEY_SIZE * 2) {
                string publicKeyString = body.substr(11);
                std::transform(publicKeyString.begin(), publicKeyString.end(), publicKeyString.begin(), ::tolower); //For comparison with pending friend requests

                //Check if pending friend request exists for given public key

                int i;
                for (i = 0; i < friendRequestPublicKeyList.size(); i++) {
                    if (friendRequestPublicKeyList.at(i) == publicKeyString) {
                        break;
                    }
                }

                if (i != friendRequestPublicKeyList.size()) {
                    uint8_t *uintPublicKeyArray = new uint8_t[TOX_PUBLIC_KEY_SIZE];
                    hexToByte(string((char *) message + 14, TOX_PUBLIC_KEY_SIZE * 2), uintPublicKeyArray, TOX_PUBLIC_KEY_SIZE);

                    uint32_t friendNumber = tox_friend_add_norequest(tox, uintPublicKeyArray, NULL);

                    if (friendNumber == UINT32_MAX) {
                        writeToLog("Failed to add friend");
                        return;
                    }

                    writeToLog(string("Added friend ") + publicKeyString + " (friend number: " + to_string(friendNumber) + ")");

                    saveTox();

                    //Remove friend request from list

                    friendRequestPublicKeyList.erase(friendRequestPublicKeyList.begin() + i);

                    delete[] uintPublicKeyArray;
                    return;
                } else {
                    writeToLog("No pending friend request could be found for the given public key");
                }
            } else {
                writeToLog("Wrong length for public key");
            }
        } else if (body.find(" decline_fr ") == 0 && body.length() > 12) {
            if (body.length() == 12 + TOX_PUBLIC_KEY_SIZE * 2) {
                string publicKeyString = body.substr(12);
                std::transform(publicKeyString.begin(), publicKeyString.end(), publicKeyString.begin(), ::tolower); //For comparison with pending friend requests

                //Check if pending friend request exists for given public key

                int i;
                for (i = 0; i < friendRequestPublicKeyList.size(); i++) {
                    if (friendRequestPublicKeyList.at(i) == publicKeyString) {
                        break;
                    }
                }

                if (i != friendRequestPublicKeyList.size()) {
                    //Remove friend request from list

                    friendRequestPublicKeyList.erase(friendRequestPublicKeyList.begin() + i);

                    writeToLog("Removed friend request from public key " + publicKeyString);

                    return;
                } else {
                    writeToLog("No pending friend request could be found for the given public key");
                }
            } else {
                writeToLog("Wrong length for public key");
            }
        } else if (body.find(" add ") == 0 && body.length() > 5) {
            if (body.length() == 5 + TOX_ADDRESS_SIZE * 2) {
                string addressString = body.substr(5);
                std::transform(addressString.begin(), addressString.end(), addressString.begin(), ::tolower); //For comparison with pending friend requests

                uint8_t *uintAddressArray = new uint8_t[TOX_ADDRESS_SIZE];
                hexToByte(string((char *) message + 8, TOX_ADDRESS_SIZE * 2), uintAddressArray, TOX_ADDRESS_SIZE);

                //Check if pending friend request exists for the given address
                //If one exists, use tox_friend_add_norequest()

                int i;
                for (i = 0; i < friendRequestPublicKeyList.size(); i++) {
                    if (addressString.find(friendRequestPublicKeyList.at(i)) == 0) { //Given address has public key from friend request
                        break;
                    }
                }

                uint32_t friendNumber;

                if (i != friendRequestPublicKeyList.size()) {
                    friendNumber = tox_friend_add_norequest(tox, uintAddressArray, NULL); //Does not use any further bytes from address than TOX_PUBLIC_KEY_SIZE
                } else {
                    friendNumber = tox_friend_add(tox, uintAddressArray, (uint8_t *) "Please add me on Tox", 20, NULL);
                }

                if (friendNumber == UINT32_MAX) {
                    writeToLog("Failed to add friend");
                    return;
                } else if (i != friendRequestPublicKeyList.size()) {
                    //If a pending friend request exists, remove it from the list now
                    friendRequestPublicKeyList.erase(friendRequestPublicKeyList.begin() + i);
                }

                writeToLog(string("Added friend ") + addressString + " (friend number: " + to_string(friendNumber) + ")");

                saveTox();

                delete[] uintAddressArray;
                return;
            } else {
                writeToLog("Wrong length for friend address");
            }
        } else if (body.find(" delete_friend ") == 0 && body.length() > 15) {
            string friendNumberString = body.substr(15);
            uint32_t friendNumber;

            try {
                friendNumber = stoul(friendNumberString);
            } catch (...) {
                writeToLog("Failed to parse friend number");
                return;
            }

            if (friendNumber == redirectionFriendNumber) {
                writeToLog("Cannot remove redirection target from friend list!");
                return;
            }

            TOX_ERR_FRIEND_DELETE *error = new TOX_ERR_FRIEND_DELETE;

            if (tox_friend_delete(tox, friendNumber, error)) {
                //Delete pending messages for given friend number as it can be reused later

                if (messageQueueMap.count(friendNumber) > 0) {
                    messageQueueMap.erase(friendNumber);
                }

                writeToLog("Removed friend #" + to_string(friendNumber));
            } else if (*error = TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND) {
                writeToLog("Could not find friend for given friend number: " + to_string(friendNumber));
            } else {
                writeToLog("Failed to delete friend #" + to_string(friendNumber));
            }

            delete error;
            return;
        } else {
            writeToLog("Could not interpret command");
        }
    }

    string friendNumberString = to_string(friendNumber);
    string friendNumberLengthString = to_string(friendNumberString.length());
    string messageLengthString = to_string(messageLength);

    size_t infoLength = 3 + friendNumberLengthString.length() + 1 + messageLengthString.length() + 1 + friendNumberString.length() + 1;
    size_t messagePartLength = min(messageLength, TOX_MAX_MESSAGE_LENGTH - infoLength); //TODO: Split very long messages into two parts
    size_t sendMessageLength = infoLength + messagePartLength;

    uint8_t *sendMessage = new uint8_t[sendMessageLength];
    memcpy(sendMessage, (type == TOX_MESSAGE_TYPE_NORMAL) ? "20 " : "21 ", 3);
    memcpy(sendMessage + 3, friendNumberLengthString.c_str(), friendNumberLengthString.length());
    sendMessage[3 + friendNumberLengthString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1, messageLengthString.c_str(), messageLengthString.length());
    sendMessage[3 + friendNumberLengthString.length() + 1 + messageLengthString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + messageLengthString.length() + 1, friendNumberString.c_str(), friendNumberString.length());
    sendMessage[3 + friendNumberLengthString.length() + 1 + messageLengthString.length() + 1 + friendNumberString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + messageLengthString.length() + 1 + friendNumberString.length() + 1, message, messageLength);

    TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
    sendMessageWithQueue(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, sendMessage, sendMessageLength, sendError);

    if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
        writeToLog(string("Redirected message \"") + string((char *) sendMessage, sendMessageLength) + "\"");
    } else {
        writeToLog(string("Redirecting message \"") + string((char *) sendMessage, sendMessageLength) + "\" failed");
    }

    delete sendError;
    delete[] sendMessage;
}

void Server::callbackFriendMessageReceived(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendMessageReceived(friend_number, type, message, length);
}

void Server::sendMessageWithQueue(Tox *tox, uint32_t friendNumber, TOX_MESSAGE_TYPE messageType, uint8_t *message, size_t messageLength, TOX_ERR_FRIEND_SEND_MESSAGE *error) {
    tox_friend_send_message(tox, friendNumber, messageType, message, messageLength, error);

    if (*error == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
        //Check if queue exists, if not, create it

        if (messageQueueMap.count(friendNumber) == 0) {
            messageQueueMap[friendNumber] = new std::queue<string>;
        }

        messageQueueMap[friendNumber]->push(string((char *) message, messageLength));

        writeToLog("Put message in queue");
    }
}

void Server::friendConnectionStatusChanged(Tox *tox, uint32_t friendNumber, TOX_CONNECTION connectionStatus) {
    bool friendConnected = (connectionStatus != TOX_CONNECTION_NONE);

    if (friendNumber != redirectionFriendNumber) {
        //Notify client of connection status changes while he is online

        sendFriendUpdate(friendNumber);
    } else if (friendConnected) { //TODO: Friend added/removed messages
        //Update client about what happened in its absence
        //Iterate through all friends and send updates if something has changed

        size_t friendCount = tox_self_get_friend_list_size(tox);

        uint32_t *friendList = new uint32_t[friendCount];
        tox_self_get_friend_list(tox, friendList);

        for (int i = 0; i < friendCount; i++) {
            uint32_t friendNumber = friendList[i];

            if (friendNumber != redirectionFriendNumber) {
                sendFriendUpdate(friendNumber, ONLY_CHANGES);
            }
        }

        delete[] friendList;
    }

    //Try to resend messages

    if (friendConnected && messageQueueMap.count(friendNumber) == 1) {
        std::queue<string> *queue = messageQueueMap[friendNumber];

        while (!queue->empty()) {
            string messageString = queue->front();

            uint8_t *message = new uint8_t[messageString.length()];
            memcpy(message, messageString.c_str(), messageString.length());

            TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
            tox_friend_send_message(tox, friendNumber, TOX_MESSAGE_TYPE_NORMAL, message, messageString.length(), sendError);

            if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                writeToLog(string("Resent message \"") + string((char *) message, messageString.length()) + "\"");
                queue->pop();
            } else if (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
                writeToLog(string("Resending message \"") + string((char *) message, messageString.length()) + "\" failed (friend offline again, will try again later)");
                delete sendError;
                delete[] message;
                break;
            } else {
                writeToLog(string("Resending message \"") + string((char *) message, messageString.length()) + "\" failed");
            }

            delete sendError;
            delete[] message;
        }
    }
}

void Server::callbackFriendConnectionStatus(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data) {
    static_cast<Server *>(user_data)->friendConnectionStatusChanged(tox, friend_number, connection_status);
}

void Server::friendNameChanged(Tox *tox, uint32_t friendNumber, const uint8_t *name, size_t length) {
    if (friendNumber == redirectionFriendNumber) {
        return;
    }

    sendFriendUpdate(friendNumber);
}

void Server::callbackFriendName(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendNameChanged(tox, friend_number, name, length);
}

void Server::friendStatusMessageChanged(Tox *tox, uint32_t friendNumber, const uint8_t *message, size_t length) {
    if (friendNumber == redirectionFriendNumber) {
        return;
    }

    sendFriendUpdate(friendNumber);
}

void Server::callbackFriendStatusMessage(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, void *user_data) {
    static_cast<Server *>(user_data)->friendStatusMessageChanged(tox, friend_number, message, length);
}

void Server::sendPendingFriendRequestList() {
    if (friendRequestPublicKeyList.size() > 0) {
        for (int i = 0; i < friendRequestPublicKeyList.size(); i++) {
            string publicKey = friendRequestPublicKeyList.at(i);

            size_t sendMessageLength = 3 + TOX_PUBLIC_KEY_SIZE * 2;

            uint8_t *sendMessage = new uint8_t[sendMessageLength];
            memcpy(sendMessage, (i == friendRequestPublicKeyList.size() - 1) ? "34 " : "33 ", 3);
            memcpy(sendMessage + 3, publicKey.c_str(), TOX_PUBLIC_KEY_SIZE * 2);

            TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
            tox_friend_send_message(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, sendMessage, sendMessageLength, sendError);

            if (*sendError != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                writeToLog("Failed to send friend request with public key " + publicKey);
            }

            delete sendError;
            delete[] sendMessage;
        }

        writeToLog("Sent friend request list");
    } else {
        TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
        tox_friend_send_message(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) "35", 2, sendError);

        bool success = (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

        if (success) {
            writeToLog("Sent empty friend request list message");
        } else {
            writeToLog("Failed to send empty friend request list message");
        }

        delete sendError;
    }
}

void Server::friendStatusChanged(Tox *tox, uint32_t friendNumber, TOX_USER_STATUS status) {
    if (friendNumber == redirectionFriendNumber) {
        return;
    }
    writeToLog("friendUpdate because of changed status");
    sendFriendUpdate(friendNumber);
}

void Server::callbackFriendStatus(Tox *tox, uint32_t friend_number, TOX_USER_STATUS status, void *user_data) {
    static_cast<Server *>(user_data)->friendStatusChanged(tox, friend_number, status);
}

void Server::sendFriendList() {
    size_t friendCount = tox_self_get_friend_list_size(tox);

    if (friendCount > 1) { //When friendCount == 1, the only friend which exists is the client
        uint32_t *friendList = new uint32_t[friendCount];
        tox_self_get_friend_list(tox, friendList);

        bool redirectionIsLast = (friendList[friendCount - 1] == redirectionFriendNumber);

        for (int i = 0; i < friendCount; i++) {
            uint32_t friendNumber = friendList[i];

            if (friendNumber != redirectionFriendNumber) {
                sendFriendUpdate(friendNumber, (i == friendCount - 1 || (redirectionIsLast && i == friendCount - 2)) ? FRIENDLIST_END : FRIENDLIST_ITEM);
            }
        }

        writeToLog("Sent friend list");

        delete[] friendList;
    } else {
        TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
        tox_friend_send_message(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) "32", 2, sendError);

        bool success = (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

        if (success) {
            writeToLog("Sent empty friend list message");
        } else {
            writeToLog("Failed to send empty friend list message");
        }

        delete sendError;
    }
}

//TODO: Use name when friend was last seen
//TODO: Schedule update method which sends all updates when a client comes online at once (by waiting for a short period of time after the first update) (NOT when friend list or only changes?)

/*
 * Returns true on success
 */
bool Server::sendFriendUpdate(uint32_t friendNumber, FriendUpdateMode mode) {
    if (friendNumber == redirectionFriendNumber) {
        writeToLog("Cannot send update about redirection target");
        return false;
    }

    bool friendConnected = (tox_friend_get_connection_status(tox, friendNumber, NULL) != TOX_CONNECTION_NONE);

    size_t nameSize = tox_friend_get_name_size(tox, friendNumber, NULL);

    if (nameSize == SIZE_MAX) {
        writeToLog("Failed to get friend name size");
        return false;
    }

    uint8_t *name = new uint8_t[nameSize];
    bool success = tox_friend_get_name(tox, friendNumber, name, NULL);

    if (!success) {
        writeToLog("Failed to get friend name");
        delete[] name;
        return false;
    }

    size_t statusMessageSize = tox_friend_get_status_message_size(tox, friendNumber, NULL);

    if (statusMessageSize == SIZE_MAX) {
        writeToLog("Failed to get status message size");
        delete[] name;
        return false;
    }

    uint8_t *statusMessage = new uint8_t[statusMessageSize];
    success = tox_friend_get_status_message(tox, friendNumber, statusMessage, NULL);

    if (!success) {
        writeToLog("Failed to get status message");
        delete[] name;
        delete[] statusMessage;
        return false;
    }

    //Return in case nothing has changed and only changes have been requested

    if (mode == ONLY_CHANGES && redirectionServerState->friendMap.count(friendNumber) > 0) {
        ServerState::Friend *savedFriend = redirectionServerState->friendMap[friendNumber];

        if (savedFriend->name != nullptr && savedFriend->nameSize == nameSize && memcmp(savedFriend->name, name, nameSize) == 0 &&
                savedFriend->statusMessage != nullptr && savedFriend->statusMessageSize == statusMessageSize && memcmp(savedFriend->statusMessage, statusMessage, statusMessageSize) == 0 &&
                savedFriend->connected == friendConnected) {

            delete[] name;
            delete[] statusMessage;
            return false;
        }
    }

    string prefix;

    switch (mode) {
    case SEND_NORMAL:
    case ONLY_CHANGES:
        prefix = "10 ";
        break;
    case FRIENDLIST_ITEM:
        prefix = "30 ";
        break;
    case FRIENDLIST_END:
        prefix = "31 ";
        break;
    }

    string friendNumberString = to_string(friendNumber);
    string friendNumberLengthString = to_string(friendNumberString.length());
    string nameLengthString = to_string(nameSize);
    string statusMessageLengthString = to_string(statusMessageSize);

    //TODO: Issue when status is empty (statusMessageSize == -1 ?)

    size_t messageLength = 3 + friendNumberLengthString.length() + 1 + nameLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 3 + nameSize + 1 + statusMessageSize;

    uint8_t *sendMessage = new uint8_t[messageLength];
    memcpy(sendMessage, prefix.c_str(), 3);
    memcpy(sendMessage + 3, friendNumberLengthString.c_str(), friendNumberLengthString.length());
    sendMessage[3 + friendNumberLengthString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1, nameLengthString.c_str(), nameLengthString.length());
    sendMessage[3 + friendNumberLengthString.length() + 1 + nameLengthString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1, statusMessageLengthString.c_str(), statusMessageLengthString.length());
    sendMessage[3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length()] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1, friendNumberString.c_str(), friendNumberString.length());
    sendMessage[3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length()] = ' ';
    sendMessage[3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 1] = friendConnected ? '1' : '0';
    sendMessage[3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 2] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 3, name, nameSize);
    sendMessage[3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 3 + nameSize] = ' ';
    memcpy(sendMessage + 3 + friendNumberLengthString.length() + 1 + statusMessageLengthString.length() + 1 + statusMessageLengthString.length() + 1 + friendNumberString.length() + 3 + nameSize + 1, statusMessage, statusMessageSize);

    TOX_ERR_FRIEND_SEND_MESSAGE *sendError = new TOX_ERR_FRIEND_SEND_MESSAGE;
    tox_friend_send_message(tox, redirectionFriendNumber, TOX_MESSAGE_TYPE_NORMAL, sendMessage, messageLength, sendError);

    success = (*sendError == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

    if (success) {
        writeToLog(string("Sent friend update for friend #") + friendNumberString);

        //Save updated information in redirectionServerState

        if (redirectionServerState->friendMap.count(friendNumber) == 0) {
            redirectionServerState->friendMap[friendNumber] = new ServerState::Friend;
        }

        ServerState::Friend *savedFriend = redirectionServerState->friendMap[friendNumber];

        //Do not modify the struct if it is already filled with the correct data
        //If it is filled with incorrect data, delete the current values and set new ones
        //If nothing above is true, set the new data

        bool equal = false;

        if (savedFriend->name != nullptr && !(equal = (savedFriend->nameSize == nameSize && memcmp(savedFriend->name, name, nameSize) == 0))) {
            savedFriend->nameSize = 0;
            delete[] savedFriend->name;
        }

        if (!equal) {
            savedFriend->name = new uint8_t[nameSize];
            memcpy(savedFriend->name, name, nameSize);
            savedFriend->nameSize = nameSize;
        }

        equal = false;

        if (savedFriend->statusMessage != nullptr && !(equal = (savedFriend->statusMessageSize == statusMessageSize && memcmp(savedFriend->statusMessage, statusMessage, statusMessageSize) == 0))) {
            savedFriend->statusMessageSize = 0;
            delete[] savedFriend->statusMessage;
        }

        if (!equal) {
            savedFriend->statusMessage = new uint8_t[statusMessageSize];
            memcpy(savedFriend->statusMessage, statusMessage, statusMessageSize);
            savedFriend->statusMessageSize = statusMessageSize;
        }

        savedFriend->connected = friendConnected;
    } else {
        writeToLog(string("Failed to send friend update for friend #") + friendNumberString);
    }

    delete sendError;
    delete[] name;
    delete[] statusMessage;
    delete[] sendMessage;

    return success;
}

string Server::intToString(int value, int digits) {
    string result = to_string(value);

    while (result.length() < digits) {
        result = '0' + result;
    }

    return result;
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
void Server::writeToLog(const string &text) {
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

void Server::loadGlobalConfig() {
    ifstream loadFile(getDataDir() + "global.conf");

    if (!loadFile) {
        writeToLog("Failed to open global config file for loading");
        return;
    }

    string line;

    while (getline(loadFile, line)) {
        if (line.find(CONFIG_WRITE_LOG_TO_COUT) == 0) {
            string value = line.substr(15); //CONFIG_WRITE_LOG_TO_COUT.length()
            std::transform(value.begin(), value.end(), value.begin(), ::tolower);
            writeLogToCout = (value == "true");
        } else {
            writeToLog("Global config: Could not interpret line");
        }
    }

    loadFile.close();

    writeToLog("Loaded global config");
}

void Server::loadConfig() {
    ifstream loadFile(getDataDir() + "profile_000.conf");

    if (!loadFile) {
        writeToLog("Failed to open profile config file for loading");
        return;
    }

    string line;

    while (getline(loadFile, line)) {
        if (line.find(CONFIG_REDIRECTION_PUB_KEY) == 0) {
            string pubKey = line.substr(18); //CONF_REDIRECTION_PUB_KEY.length()
            if (pubKey.length() == TOX_PUBLIC_KEY_SIZE * 2) {
                uint8_t *pubKeyArray = new uint8_t[TOX_PUBLIC_KEY_SIZE];

                hexToByte(pubKey, pubKeyArray, TOX_PUBLIC_KEY_SIZE);

                uint32_t friendNumber = tox_friend_by_public_key(tox, pubKeyArray, NULL);
                if (friendNumber != UINT32_MAX) {
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
            writeToLog("Profile config: Could not interpret line");
        }
    }

    loadFile.close();

    writeToLog("Loaded profile config");
}

void Server::saveConfig() {
    ofstream saveFile(getDataDir() + "profile_000.conf");

    if (!saveFile) {
        writeToLog("Failed to open profile config file for saving");
        return;
    }

    if (!redirectionPubKey.empty()) {
        saveFile << CONFIG_REDIRECTION_PUB_KEY << redirectionPubKey << endl;
    }

    writeToLog("Saved profile config");

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
