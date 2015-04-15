#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <iostream>
#include <cstring>

#include "config.h"
#include "server.h"

using namespace std;

void createDataDir();

int main() {
    //Wait one second before starting the server to make sure that we
    //have write access to the required directories on Snappy Ubuntu Core
    //when the service is started directly after installing the package
    //for the first time.
//    usleep(10000000); //TODO: Remove the ugly workaround and search for the real reason...

    //Create data directory if it does not exist
    createDataDir();

    //Start server
    Server *s = new Server();
    s->startLoop();

    return 0;
}

void createDataDir() {
    string dataDirString = string(DATA_DIR);

    //If the data dir contains a tilde, replace it with the user's home directory

    if (DATA_DIR[0] == '~') {
        char *homeDir = getpwuid(getuid())->pw_dir;
        dataDirString = string(homeDir) + dataDirString.substr(1);
    }

    //Check if data dir exists. If not, create it.

    struct stat st;
    if (stat(dataDirString.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (mkdir(dataDirString.c_str(), 0740) != -1) {
            cout << "Successfully created data directory" << endl;
        } else {
            cerr << "Failed to create data directory: " << strerror(errno) << endl;
        }
    }
}
