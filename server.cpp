#include "server.h"

#include <iostream>
#include <iomanip>
#include <fstream>

#include <unistd.h>

using namespace std;

Server::Server() {
    //Create tox object

    Tox_Options toxOptions;
    toxOptions.proxy_type = TOX_PROXY_NONE;
    toxOptions.proxy_address[0] = 0;
    toxOptions.proxy_port = 0;

    tox = tox_new(&toxOptions);

    if (tox == NULL) {
        cerr << "toxcore failed to start" << endl;
        return;
    }

    //Print tox id to the logs

    uint8_t friendAddress[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox, friendAddress);

    writeToLog(byteToHex(friendAddress, TOX_FRIEND_ADDRESS_SIZE));

    //Set identity information

    tox_set_name(tox, (uint8_t *) "Tox bot", 7);
    tox_set_status_message(tox, (uint8_t *) "Replying to your messages", 25);
    tox_set_user_status(tox, TOX_USERSTATUS_NONE);

    //Bootstrap

    int bootstrapResult = tox_bootstrap_from_address(tox, "192.254.75.102", 33445, new uint8_t[32] {
                                   0x95, 0x1C, 0x88, 0xB7, 0xE7, 0x5C, 0x86, 0x74, 0x18, 0xAC, 0xDB, 0x5D, 0x27, 0x38, 0x21, 0x37,
                                   0x2B, 0xB5, 0xBD, 0x65, 0x27, 0x40, 0xBC, 0xDF, 0x62, 0x3A, 0x4F, 0xA2, 0x93, 0xE7, 0x5D, 0x2F
                                   });

    writeToLog("Bootstrap: " + std::to_string(bootstrapResult));

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
            writeToLog("Connected: " + std::to_string(connected));
        }

        usleep(tox_do_interval(tox));
    }
}

string Server::byteToHex(uint8_t *data, uint16_t length) {
    char hexString[length * 2];
    static const char hexChars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for(int j = 0; j < length; j++){
        hexString[j*2] = hexChars[((data[j] >> 4) & 0xF)];
        hexString[(j*2) + 1] = hexChars[(data[j]) & 0x0F];
    }

    return string(hexString, length * 2);
}

//Automatically add everyone who adds the bot
void Server::friendRequestReceived(const uint8_t *public_key) {
    writeToLog("Received friend request");
    tox_add_friend_norequest(tox, public_key);
}

void Server::callbackFriendRequestReceived(Tox *tox, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata) {
    static_cast<Server *>(userdata)->friendRequestReceived(public_key);
}

//Simply reply to all messages by sending back the same one
void Server::friendMessageReceived(int32_t friendnumber, const uint8_t * message, uint16_t length) {
    tox_send_message(tox, friendnumber, message, length);
}

void Server::callbackFriendMessageReceived(Tox *tox, int32_t friendnumber, const uint8_t * message, uint16_t length, void *userdata) {
    static_cast<Server *>(userdata)->friendMessageReceived(friendnumber, message, length);
}

/*
 * Writes to log file on snappy systems, otherwise to cout
 */
void Server::writeToLog(const string &text) {
    ofstream logfile("/var/lib/apps/tox-redirection-server.nikwen/0.0.1/log.txt", std::ios_base::out | std::ios_base::app); //TODO: Version number via config.h.in

    if (logfile) {
        logfile << text << std::endl;
    } else {
        cout << text << std::endl;
        return;
    }
}

void Server::saveTox() {
    ofstream saveFile("/var/lib/apps/tox-redirection-server.nikwen/0.0.1/profile.tox");

    if (!saveFile) {
        writeToLog("Failed to open tox id file");
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

    
}
