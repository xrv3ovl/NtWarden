#include "pch.h"
#include "ServerHandler.h"
#include "DriverHelper.h"
#include "..\NtWarden\WinSysProtocol.h"
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

static void PrintUsage(const char* exe) {
	printf("Usage: %s [--port <port>] [--install]\n", exe);
	printf("  --port <port>  Listen port (default: %d)\n", WINSYS_DEFAULT_PORT);
	printf("  --install      Install and start the KWinSys driver (requires admin)\n");
}

int main(int argc, char* argv[]) {
	int port = WINSYS_DEFAULT_PORT;
	bool installDriver = false;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port = atoi(argv[++i]);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "Invalid port number: %d\n", port);
				return 1;
			}
		}
		else if (strcmp(argv[i], "--install") == 0) {
			installDriver = true;
		}
		else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			PrintUsage(argv[0]);
			return 0;
		}
	}

	// Initialize Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
		return 1;
	}

	// Install driver if requested
	if (installDriver && !DriverHelper::IsDriverLoaded()) {
		printf("[*] Installing KWinSys driver...\n");
		if (DriverHelper::InstallDriver()) {
			printf("[+] Driver installed successfully\n");
			if (DriverHelper::LoadDriver()) {
				printf("[+] Driver started successfully\n");
			}
			else {
				fprintf(stderr, "[!] Driver installed but failed to start (error %lu)\n", ::GetLastError());
			}
		}
		else {
			fprintf(stderr, "[!] Driver installation failed (are you running as admin?)\n");
		}
	}

	// Check kernel driver status
	if (DriverHelper::IsDriverLoaded()) {
		printf("[+] KWinSys kernel driver is loaded\n");
		printf("[+] Driver version: 0x%04X\n", DriverHelper::GetVersion());
	}
	else {
		printf("[!] KWinSys kernel driver is NOT loaded\n");
		printf("[!] Kernel-mode features will return WINSYS_STATUS_NO_DRIVER\n");
		printf("[!] Install and start the driver for full functionality\n");
	}

	// Create listening socket
	SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSock == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Allow port reuse
	int optval = 1;
	setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons((u_short)port);

	if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
		closesocket(listenSock);
		WSACleanup();
		return 1;
	}

	if (listen(listenSock, 1) == SOCKET_ERROR) {
		fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
		closesocket(listenSock);
		WSACleanup();
		return 1;
	}

	printf("[+] WinSysServer listening on 0.0.0.0:%d\n", port);
	printf("[+] Waiting for client connection...\n");

	ServerHandler handler;

	while (true) {
		sockaddr_in clientAddr{};
		int clientAddrLen = sizeof(clientAddr);
		SOCKET clientSock = accept(listenSock, (sockaddr*)&clientAddr, &clientAddrLen);

		if (clientSock == INVALID_SOCKET) {
			fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
			continue;
		}

		char clientIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
		printf("[+] Client connected: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));

		// Disable Nagle's algorithm for lower latency
		int nodelay = 1;
		setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

		handler.HandleClient(clientSock);

		closesocket(clientSock);
		printf("[-] Client disconnected: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));
	}

	closesocket(listenSock);
	WSACleanup();
	return 0;
}
