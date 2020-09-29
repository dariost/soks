/*
    Copyright 2020 | Dario Ostuni <dario.ostuni@gmail.com>

    This Source Code Form is subject to the terms of the
    Mozilla Public License, v. 2.0. If a copy of the MPL
    was not distributed with this file, You can obtain
    one at https://mozilla.org/MPL/2.0/.
*/

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define max(a, b) ((a) > (b) ? (a) : (b))

void print_usage_and_exit(FILE* f, const char* program_name, int exit_code) {
    fprintf(f,
            "Usage: %s -i <interface>\n"
            "\n"
            "    Soks is a minimalistic SOCKS5 proxy over a network interface (like a VPN or\n"
            "    a second physical network device)\n"
            "\n"
            "    -i <interface>    set the network interface name to redirect the traffic to\n"
            "    -l <address>      set the address to listen to (default 127.0.0.1)\n"
            "    -p <port>         set the port to listen to (default 1080)\n"
            "    -n <niceness>     increase niceness for the children processes (default 10)\n"
            "    -t <timeout>      set the timeout (in seconds) for connections (default 60)\n"
            "    -v                be verbose (default false)\n"
            "    -h, --help        print this help\n"
            "\n"
            "Usage example: %s -i tun0 -l 127.0.0.1 -p 1080\n"
            "\n"
            "Soks was written by Dario Ostuni <dario.ostuni@gmail.com>\n"
            "The code is licensed under the MPL2 licence <http://mozilla.org/MPL/2.0/>\n"
            "The project repository can be found at https://github.com/dariost/soks\n",
            program_name, program_name);
    exit(exit_code);
}

int main(int argc, char* argv[]) {
    signal(SIGCHLD, SIG_IGN);
    const size_t BUFFER_SIZE = (1UL << 16);
    uint8_t buffer[BUFFER_SIZE];
    char domain_buffer[256] = {0};
    const char* interface_name = NULL;
    uint16_t listen_port = 1080;
    const char* listen_address = "127.0.0.1";
    int niceness_increase = 10;
    bool verbose = false;
    time_t timeout_seconds = 60;
    for(size_t i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-i") == 0 && i < argc - 1) {
            interface_name = argv[++i];
        } else if(strcmp(argv[i], "-l") == 0 && i < argc - 1) {
            listen_address = argv[++i];
        } else if(strcmp(argv[i], "-p") == 0 && i < argc - 1) {
            listen_port = atoi(argv[++i]);
        } else if(strcmp(argv[i], "-t") == 0 && i < argc - 1) {
            timeout_seconds = atoi(argv[++i]);
        } else if(strcmp(argv[i], "-n") == 0 && i < argc - 1) {
            niceness_increase = atoi(argv[++i]);
        } else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage_and_exit(stdout, argv[0], EXIT_SUCCESS);
        } else if(strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else {
            fprintf(stdout, "Invalid argument: %s\n\n", argv[i]);
            print_usage_and_exit(stdout, argv[0], EXIT_FAILURE);
        }
    }
    if(!interface_name) {
        fprintf(stdout, "Mandatory argument -i missing\n\n");
        print_usage_and_exit(stdout, argv[0], EXIT_FAILURE);
    }
    errno = 0;
    int listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if(listen_socket < 0) {
        fprintf(stdout, "Cannot create listen socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int yes = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    struct sockaddr_in server_address, client_address, remote_address, local_address;
    socklen_t local_address_size = sizeof(struct sockaddr_in);
    memset(&server_address, 0, sizeof(struct sockaddr_in));
    memset(&remote_address, 0, sizeof(struct sockaddr_in));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(listen_port);
    if(!inet_aton(listen_address, (struct in_addr*)&server_address.sin_addr.s_addr)) {
        fprintf(stdout, "Invalid listen address: %s\n", listen_address);
        exit(EXIT_FAILURE);
    }
    errno = 0;
    if(bind(listen_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        fprintf(stdout, "Cannot bind server socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(listen(listen_socket, SOMAXCONN) < 0) {
        fprintf(stdout, "Cannot listen server socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(true) {
        socklen_t client_size = sizeof(struct sockaddr_in);
        errno = 0;
        int client_socket = accept(listen_socket, (struct sockaddr*)&client_address, &client_size);
        if(client_socket < 0) {
            fprintf(stdout, "Cannot accept incoming connection: %s\n", strerror(errno));
            continue;
        }
        if(verbose) {
            fprintf(stdout, "Client connected: %s:%hu\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
        }
        pid_t pid = fork();
        if(pid) {
            close(client_socket);
            continue;
        }
        close(listen_socket);
        nice(niceness_increase);
        errno = 0;
        ssize_t ret = read(client_socket, buffer, BUFFER_SIZE);
        if(ret < 0) {
            fprintf(stdout, "Cannot read from client socket: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if(ret < 3 || buffer[0] != 0x05 || buffer[1] != ret - 2) {
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        bool ok = false;
        for(size_t i = 0; i < buffer[1] && !ok; i++) {
            ok = buffer[i + 2] == 0;
        }
        uint8_t method_response[2] = {0x05, ok ? 0x00 : 0xFF};
        ret = write(client_socket, &method_response, 2);
        if(ret != 2 || !ok) {
            close(client_size);
            exit(EXIT_FAILURE);
        }
        ret = read(client_socket, buffer, BUFFER_SIZE);
        uint8_t connect_response[10] = {0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if(ret < 5 || buffer[0] != 0x05 || buffer[1] != 0x01 || buffer[2] != 0x00) {
            write(client_socket, connect_response, 10);
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        remote_address.sin_family = AF_INET;
        if(buffer[3] == 0x01) {
            if(ret != 10) {
                write(client_socket, connect_response, 10);
                close(client_socket);
                exit(EXIT_FAILURE);
            }
            memcpy(&remote_address.sin_addr, &buffer[4], 4);
            memcpy(&remote_address.sin_port, &buffer[8], 2);
        } else if(buffer[3] == 0x03) {
            size_t domain_length = buffer[4];
            if(ret != domain_length + 7) {
                write(client_socket, connect_response, 10);
                close(client_socket);
                exit(EXIT_FAILURE);
            }
            memcpy(domain_buffer, &buffer[5], domain_length);
            memcpy(&remote_address.sin_port, &buffer[domain_length + 5], 2);
            struct hostent* host = gethostbyname(domain_buffer);
            if(!host || host->h_addrtype != AF_INET || !host->h_addr) {
                write(client_socket, connect_response, 10);
                close(client_socket);
                exit(EXIT_FAILURE);
            }
            memcpy(&remote_address.sin_addr, host->h_addr, 4);
        } else {
            write(client_socket, connect_response, 10);
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        if(verbose) {
            fprintf(stdout, "Client %s:%hu is trying", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
            fprintf(stdout, " to connect to %s:%hu\n", inet_ntoa(remote_address.sin_addr), ntohs(remote_address.sin_port));
        }
        int remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if(remote_socket < 0) {
            write(client_socket, connect_response, 10);
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        setsockopt(remote_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name) + 1);
        if(connect(remote_socket, (struct sockaddr*)&remote_address, sizeof(struct sockaddr_in)) < 0) {
            write(client_socket, connect_response, 10);
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        if(getsockname(client_socket, (struct sockaddr*)&local_address, &local_address_size) < 0) {
            write(client_socket, connect_response, 10);
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        connect_response[1] = 0;
        memcpy(&connect_response[4], &local_address.sin_addr, 4);
        memcpy(&connect_response[8], &local_address.sin_port, 2);
        if(write(client_socket, connect_response, 10) != 10) {
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        if(verbose) {
            fprintf(stdout, "Client %s:%hu successfully", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
            fprintf(stdout, " connected to %s:%hu\n", inet_ntoa(remote_address.sin_addr), ntohs(remote_address.sin_port));
        }
        while(true) {
            fd_set fv;
            FD_ZERO(&fv);
            FD_SET(client_socket, &fv);
            FD_SET(remote_socket, &fv);
            struct timeval timeout = {.tv_sec = timeout_seconds, .tv_usec = 0};
            errno = 0;
            int res = select(max(client_socket, remote_socket) + 1, &fv, NULL, NULL, &timeout);
            if(res <= 0) {
                if(ret < 0 && errno == EINTR) {
                    continue;
                }
                close(client_socket);
                close(remote_socket);
                exit(EXIT_FAILURE);
            } else {
                int sender = FD_ISSET(client_socket, &fv) ? client_socket : remote_socket;
                int receiver = sender == client_socket ? remote_socket : client_socket;
                errno = 0;
                ret = read(sender, buffer, BUFFER_SIZE);
                if(ret <= 0) {
                    if(ret < 0 && errno == EINTR) {
                        continue;
                    }
                    close(client_socket);
                    close(remote_socket);
                    exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
                } else {
                    size_t written = 0;
                    size_t total = ret;
                    while(written < total) {
                        ret = write(receiver, buffer + written, total - written);
                        if(ret <= 0) {
                            if(ret < 0 && errno == EINTR) {
                                continue;
                            }
                            close(client_socket);
                            close(remote_socket);
                            exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
                        } else {
                            written += ret;
                        }
                    }
                }
            }
        }
        break;
    }
    return EXIT_SUCCESS;
}
