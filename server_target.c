#include <WinSock2.h>
#include <Windows.h>

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define SOCK5_VER_ID			0x05
#define SOCK5_METHOD_NO_AUTH_REQUIRED	0x00

#define MAX_BUFFER			512
#define MAX_METHODS			255

#define SOCK5_MAX_DMN_NAME_LEN		0xFF


struct sock_ver_id_msg {
	uint8_t ver;
	uint8_t nmethods;
	uint8_t methods[MAX_METHODS];
};

struct sock_method_sel_msg {
	uint8_t ver;
	uint8_t method;
};

struct sock5_dmn_name {
	uint8_t len;
	char name[SOCK5_MAX_DMN_NAME_LEN];
};

struct sock5_msg {
	uint8_t ver;
	union {
		uint8_t cmd;
		uint8_t rep;
	};
	uint8_t rsv;
	uint8_t atyp;
	union {
		uint8_t ipv4_addr[4];
		uint8_t ipv6_addr[16];
		struct sock5_dmn_name dmn_name;
	};
	uint16_t dst_port;
};

int recv_buf(SOCKET s, void *buf, uint32_t count)
{
	while (count) {
		int to_recv, rcvd;
		to_recv = count < MAX_BUFFER ?
			count : MAX_BUFFER;
		if ((rcvd = recv(s, buf, to_recv, 0)) == INVALID_SOCKET || rcvd == 0)
			return 0;
		buf = (char *)buf + rcvd;
		count -= rcvd;
	}
	return 1;
}

int send_buf(SOCKET s, void *buf, uint32_t count)
{
	while (count) {
		uint32_t to_send, sent;
		to_send = count < MAX_BUFFER ? count : MAX_BUFFER;
		if ((sent = send(s, buf, to_send, 0)) == SOCKET_ERROR)
			return 0;
		buf = (char *)buf + sent;
		count -= sent;
	}
	return 1;
}

static int find_method(uint8_t *methods, uint8_t count, uint8_t method_type)
{
	while (count--)
		if (*methods++ == method_type)
			return 1;
	return 0;
}

static int sock5_negotiate(SOCKET s)
{
	struct sock_ver_id_msg sid;
	struct sock_method_sel_msg sm;
	int res;

	res = 0;
	if (!recv_buf(s, &sid, offsetof(struct sock_ver_id_msg, methods)))
		goto cleanup;
	if (!recv_buf(s, sid.methods, sid.nmethods))
		goto cleanup;
	if (sid.ver != SOCK5_VER_ID)
		goto cleanup;
	if (!find_method(sid.methods, sid.nmethods, SOCK5_METHOD_NO_AUTH_REQUIRED))
		goto cleanup;
	sm.ver = SOCK5_VER_ID;
	sm.method = SOCK5_METHOD_NO_AUTH_REQUIRED;
	if (!send_buf(s, &sm, sizeof(sm)))
		goto cleanup;
	res = 1;
cleanup:
	return res;
}

#define SOCK5_ADDR_TYPE_IPV4	0x01
#define SOCK5_ADDR_TYPE_DNAME	0x03
#define SOCK5_ADDR_TYPE_IPV6	0x04

static int sock5_recv_request(SOCKET s, struct sock5_msg *req)
{
	int res;
	if (!recv_buf(s, req, offsetof(struct sock5_msg, dmn_name)))
		return 0;
	switch (req->atyp) {
	case SOCK5_ADDR_TYPE_IPV4:
		res =  recv_buf(s, req->ipv4_addr, sizeof(req->ipv4_addr));
		break;
	case SOCK5_ADDR_TYPE_DNAME:
		if (!recv_buf(s, &req->dmn_name.len, sizeof(req->dmn_name.len)))
			return 0;
		res = recv_buf(s, &req->dmn_name.name, req->dmn_name.len);
		break;
	case SOCK5_ADDR_TYPE_IPV6:
		res = recv_buf(s, req->ipv6_addr, sizeof(req->ipv6_addr));
		break;
	default:
		return 0;
	}
	if (!res)
		return 0;
	return recv_buf(s, &req->dst_port, sizeof(req->dst_port));
}

static int sock5_send_reply(SOCKET s, struct sock5_msg *reply)
{
	int res;
	if (!send_buf(s, reply, offsetof(struct sock5_msg, dmn_name)))
		return 0;
	switch (reply->atyp) {
	case SOCK5_ADDR_TYPE_IPV4:
		res = send_buf(s, reply->ipv4_addr, sizeof(reply->ipv4_addr));
		break;
	case SOCK5_ADDR_TYPE_DNAME:
		if (!send_buf(s, &reply->dmn_name.len, sizeof(reply->dmn_name.len)))
			return 0;
		res = send_buf(s, reply->dmn_name.name, reply->dmn_name.len);
		break;
	case SOCK5_ADDR_TYPE_IPV6:
		res = send_buf(s, reply->ipv6_addr, sizeof(reply->ipv6_addr));
		break;
	default:
		return 0;
	}
	if (!res)
		return 0;
	return send_buf(s, &reply->dst_port, sizeof(reply->dst_port));
}

#define SOCK5_CMND_CONNECT	0x01

#define SOCK5_REPLY_SUCCESS	0x00
#define SOCK5_REPLY_GEN_ERROR	0x01

static int create_tunnel(uint8_t ipv4_addr[4], uint16_t port, SOCKET *s)
{
	SOCKET sockfd;
	struct sockaddr_in service;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return 0;
	
	service.sin_family = AF_INET;
	memcpy(&service.sin_addr.S_un.S_un_b, ipv4_addr, 4);
	service.sin_port = port;
	if (connect(sockfd, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
		return 0;

	*s = sockfd;
	return 1;
}

DWORD WINAPI sock_thread(void *param)
{
	SOCKET ls, rs;
	struct sock5_msg req;
	struct sock5_msg reply;
	fd_set sfd_set;
	printf("******************--------------------------------******************\n");
	ls = (SOCKET)param;
	rs = INVALID_SOCKET;
	/* negotiate */
	if (!sock5_negotiate(ls))
		goto cleanup;
	/* get request */
	if (!sock5_recv_request(ls, &req))
		goto cleanup;
	reply = req;
	reply.rep = (req.cmd == SOCK5_CMND_CONNECT) && create_tunnel(req.ipv4_addr, req.dst_port, &rs) ?
		SOCK5_REPLY_SUCCESS : SOCK5_REPLY_GEN_ERROR;
	if (!sock5_send_reply(ls, &reply))
		goto cleanup;
	if (reply.rep != SOCK5_REPLY_SUCCESS)
		goto cleanup;		/* MUST be terminated, RFC1928, page 6 */

	/* tunnel */
	FD_ZERO(&sfd_set);
	while (1) {
		char buf[MAX_BUFFER];
		int recvd;
		SOCKET src, dest;

		/* reset them again since select clears the flag for
		 * the descriptor that isn't ready
		 */
		FD_SET(ls, &sfd_set);
		FD_SET(rs, &sfd_set);
		if (select(0, &sfd_set, NULL, NULL, NULL) == SOCKET_ERROR)
			goto cleanup;
		src = FD_ISSET(ls, &sfd_set) ? ls : rs;
		dest = src == ls ? rs : ls;
		if ((recvd = recv(src, buf, sizeof(buf), 0)) <= 0)
			goto cleanup;
		if (!send_buf(dest, buf, recvd))
			goto cleanup;
	}
cleanup:
	if (rs != INVALID_SOCKET)
		closesocket(rs);
	closesocket(ls);
	ExitThread(0);
	return 0;
}

static int create_sock_thread(SOCKET s)
{
	HANDLE handle;
	if (!(handle = CreateThread(NULL, 0, sock_thread, (void *)s, 0, 0)))
		return 0;
	CloseHandle(handle);
	
	return 1;
}

static int listener_run(USHORT port)
{
	struct sockaddr_in service;
	SOCKET sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return 0;
	service.sin_family = AF_INET;
	service.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	service.sin_port = htons(port);
	if (bind(sockfd, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR) {
		closesocket(sockfd);
		return 0;
	}
	if (listen(sockfd, SOMAXCONN))
		return 1;
	while (1) {
		SOCKET new_fd;
		new_fd = accept(sockfd, NULL, NULL);
		if (new_fd != INVALID_SOCKET) {
			printf("connection accepted\n");
			create_sock_thread(new_fd);
		}
	}
}

static int init_winsock2(void)
{
	WORD ver;
	WSADATA wd;
	ver = MAKEWORD(2, 2);
	return WSAStartup(ver, &wd) == 0;
}

int main(void)
{
	int port = 8080;
	struct sockaddr_in service;
	SOCKET sockfd;
	int con_sock;

	if (!init_winsock2())
		return 1;

	//printf("insert the port number\n");
	//scanf("%d", &port);
	//listener_run(port);
	/*Edit*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
		return 0;
	service.sin_family = AF_INET;
	service.sin_addr.S_un.S_addr = inet_addr("192.168.21.10");
	service.sin_port = htons(port);
	printf("Here\n");
	con_sock = connect(sockfd, (struct sockaddr *)&service, sizeof(service));
	if(con_sock == SOCKET_ERROR){
		printf("connect failed\n");
		return 0;
	}
	create_sock_thread(con_sock);
	printf("connect succedded\n");
	/*Edit*/
	WSACleanup();
}
