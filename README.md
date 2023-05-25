# Hserv - A simple HTTP server command line utility

## Description

Hserv is a simple but flexible HTTP server that serves as the server companion
to utilities such as Wget and Curl. The core of the application is a [single
header implementation](include/hserv.h) of an HTTP/1.1 server that supports
both unsecure and secure socket communication using OpenSSL. The server has
a simple, yet flexible, method and transfer-encoding agnostic API.

## Dependencies

* OpenSSL

## Building

    cd hserv
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX=/home/user/.local ..
    make install

## Usage

1. Serve a directory on any interface, port 8080:

    hserv <www-root>

2. Serve a single file on any interface, port 9090:

    hserv -p 9090 <file>

3. Serve data from stdin on localhost:

    echo Hello World | hserv -b 127.0.0.1

4. Securely serve a single file from a directory and immediately exit:

   hserv -s -x <www-root>

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.
