#include "stdafx.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <MSWSock.h>
#include <bcrypt.h>

#undef max
#define _CRT_RAND_S
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ws2_32.lib")

void Fatal(const char * message)
{
	printf(message);
	printf("\n");
	ExitProcess(1);
}

enum class ConnectionState
{
	Initial,
	SendingHandshake,
	ReceivingAuthOk,
	SendingQuery,
	ReceivingResultSet,
};

enum class ProtocolCapabilities : uint32_t
{
	/// <summary>
	/// No specified capabilities.
	/// </summary>
	None = 0,

	/// <summary>
	/// Use the improved version of Old Password Authentication.
	/// </summary>
	LongPassword = 1,

	/// <summary>
	/// Send found rows instead of affected rows in EOF_Packet.
	/// </summary>
	FoundRows = 2,

	/// <summary>
	/// Longer flags in Protocol::ColumnDefinition320.
	/// </summary>
	LongFlag = 4,

	/// <summary>
	/// Database (schema) name can be specified on connect in Handshake Response Packet.
	/// </summary>
	ConnectWithDatabase = 8,

	/// <summary>
	/// Do not permit database.table.column.
	/// </summary>
	NoSchema = 0x10,

	/// <summary>
	/// Supports compression.
	/// </summary>
	Compress = 0x20,

	/// <summary>
	/// Special handling of ODBC behavior.
	/// </summary>
	Odbc = 0x40,

	/// <summary>
	/// Enables the LOCAL INFILE request of LOAD DATA|XML.
	/// </summary>
	LocalFiles = 0x80,

	/// <summary>
	/// Parser can ignore spaces before '('.
	/// </summary>
	IgnoreSpace = 0x100,

	/// <summary>
	/// Supports the 4.1 protocol.
	/// </summary>
	Protocol41 = 0x200,

	/// <summary>
	/// Supports interactive and noninteractive clients.
	/// </summary>
	Interactive = 0x400,

	/// <summary>
	/// Supports SSL.
	/// </summary>
	Ssl = 0x800,

	IgnoreSigpipe = 0x1000,

	/// <summary>
	/// Can send status flags in EOF_Packet.
	/// </summary>
	Transactions = 0x2000,

	/// <summary>
	/// Supports Authentication::Native41.
	/// </summary>
	SecureConnection = 0x8000,

	/// <summary>
	/// Can handle multiple statements per COM_QUERY and COM_STMT_PREPARE.
	/// </summary>
	MultiStatements = 0x10000,

	/// <summary>
	/// Can send multiple resultsets for COM_QUERY.
	/// </summary>
	MultiResults = 0x20000,

	/// <summary>
	/// Can send multiple resultsets for COM_STMT_EXECUTE.
	/// </summary>
	PreparedStatementMultiResults = 0x40000,

	/// <summary>
	/// Sends extra data in Initial Handshake Packet and supports the pluggable authentication protocol.
	/// </summary>
	PluginAuth = 0x80000,

	/// <summary>
	/// Permits connection attributes in Protocol::HandshakeResponse41.
	/// </summary>
	ConnectionAttributes = 0x100000,

	/// <summary>
	/// Understands length-encoded integer for auth response data in Protocol::HandshakeResponse41.
	/// </summary>
	PluginAuthLengthEncodedClientData = 0x200000,

	/// <summary>
	/// Announces support for expired password extension.
	/// </summary>
	CanHandleExpiredPasswords = 0x400000,

	/// <summary>
	/// Can set SERVER_SESSION_STATE_CHANGED in the Status Flags and send session-state change data after a OK packet.
	/// </summary>
	SessionTrack = 0x800000,

	/// <summary>
	/// Can send OK after a Text Resultset.
	/// </summary>
	DeprecateEof = 0x1000000,
};

inline ProtocolCapabilities operator&(ProtocolCapabilities a, ProtocolCapabilities b) { return static_cast<ProtocolCapabilities>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b)); }
inline ProtocolCapabilities operator|(ProtocolCapabilities a, ProtocolCapabilities b) { 	return static_cast<ProtocolCapabilities>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b)); }

struct Connection
{
	ConnectionState State;
	SOCKET Socket;
	RIO_RQ RequestQueue;
	uint8_t* Buffer;
	RIO_BUF RioBuffer;
};

class PayloadReader
{
public:
	PayloadReader(const uint8_t * buffer, size_t length)
		: m_buffer{ buffer }, m_offset{ 4 }
	{
		if (length < 4)
			Fatal("received payload less than 4 bytes long");
		auto payloadLength = *reinterpret_cast<const uint32_t*>(buffer) & 0x00FFFFFF;
		if (m_offset + payloadLength > length)
			Fatal("received incomplete payload");
		m_length = m_offset + payloadLength;
	}

	uint8_t ReadByte()
	{
		return m_buffer[m_offset++];
	}

	template<typename T>
	T Read()
	{
		auto value = *reinterpret_cast<const T*>(m_buffer + m_offset);
		m_offset += sizeof(value);
		return value;
	}

	void ReadBytes(uint8_t * results, size_t length)
	{
		memcpy(results, m_buffer + m_offset, length);
		m_offset += length;
	}

	const char* ReadNullTerminatedString()
	{
		auto * psz = reinterpret_cast<const char*>(m_buffer + m_offset);
		while (m_buffer[m_offset] != 0)
			m_offset++;
		m_offset++;
		return psz;
	}

	void Skip(size_t length)
	{
		m_offset += length;
	}

	size_t GetBytesRemaining()
	{
		return m_length - m_offset;
	}

private:
	const uint8_t * const m_buffer;
	size_t m_offset;
	size_t m_length;
};

const char * g_userName = "benchmarkdbuser";
const char * g_password = "benchmarkdbpass";

HANDLE g_iocp;
RIO_CQ g_completionQueue;
OVERLAPPED g_overlapped;
RIO_EXTENSION_FUNCTION_TABLE g_rio;
const size_t BufferSize = 65536;
unsigned long long g_queries;

void ProcessPacket(Connection * connection, const RIORESULT result)
{
	switch (connection->State)
	{
	case ConnectionState::Initial:
	{
		PayloadReader reader(connection->Buffer + connection->RioBuffer.Offset, result.BytesTransferred);
		reader.ReadByte(); // protocol version
		reader.ReadNullTerminatedString(); // server version
		reader.Read<uint32_t>(); // connection ID
		uint8_t authPluginData[21] = { 0 };
		reader.ReadBytes(authPluginData, 8);
		reader.ReadByte();
		auto capabilityFlagsLow = reader.Read<uint16_t>();
		reader.ReadByte(); // character set
		reader.Read<int16_t>(); // status
		auto capabilityFlagsHigh = reader.Read<uint16_t>();
		auto capabilities = static_cast<ProtocolCapabilities>((static_cast<uint32_t>(capabilityFlagsHigh) << 16) | capabilityFlagsLow);
		auto authPluginDataLength = reader.ReadByte();
		reader.Skip(10);
		if ((capabilities & ProtocolCapabilities::SecureConnection) != ProtocolCapabilities::None)
			reader.ReadBytes(authPluginData + 8, std::max(13, authPluginDataLength - 8));

		BCRYPT_ALG_HANDLE alg;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_HASH_REUSABLE_FLAG) != ERROR_SUCCESS)
			Fatal("BCryptOpenAlgorithmProvider(BCRYPT_SHA1_ALGORITHM) failed");
		BCRYPT_HASH_HANDLE hash;
		if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG) != ERROR_SUCCESS)
			Fatal("BCryptCreateHash failed");

		BCryptHashData(hash, (PUCHAR)g_password, (ULONG)strlen(g_password), 0);
		unsigned char hashedPassword[20];
		BCryptFinishHash(hash, hashedPassword, 20, 0);

		BCryptHashData(hash, hashedPassword, 20, 0);
		unsigned char combined[40];
		BCryptFinishHash(hash, combined + 20, 20, 0);

		memcpy(combined, authPluginData, 20);
		BCryptHashData(hash, combined, 40, 0);
		unsigned char xorBytes[20];
		BCryptFinishHash(hash, xorBytes, 20, 0);

		for (int i = 0; i < 20; i++)
			hashedPassword[i] ^= xorBytes[i];

		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(alg, 0);

		uint8_t * output = connection->Buffer + 4;
		*reinterpret_cast<uint32_t*>(output) = static_cast<uint32_t>(
			ProtocolCapabilities::Protocol41 |
			ProtocolCapabilities::LongPassword |
			ProtocolCapabilities::SecureConnection |
			(capabilities & ProtocolCapabilities::PluginAuth) |
			(capabilities & ProtocolCapabilities::PluginAuthLengthEncodedClientData) |
			ProtocolCapabilities::MultiStatements |
			ProtocolCapabilities::MultiResults |
			ProtocolCapabilities::LocalFiles |
			ProtocolCapabilities::ConnectWithDatabase);
		// (serverCapabilities & ProtocolCapabilities.SessionTrack) |
		// (serverCapabilities & ProtocolCapabilities.DeprecateEof) |
		output += 4;
		*reinterpret_cast<uint32_t*>(output) = 0x40000000;
		output += 4;
		*output++ = 46; // CharacterSet.Utf8Mb4Binary;
		memset(output, 0, 23);
		output += 23;

		strcpy((char*)output, g_userName);
		output += strlen(g_userName) + 1;
		*output++ = 20;
		memcpy(output, hashedPassword, 20);
		output += 20;
		strcpy((char*)output, "hello_world");
		output += 12;
		strcpy((char*)output, "mysql_native_password");
		output += 22;
		uint32_t length = static_cast<uint32_t>(output - connection->Buffer - 4);
		*reinterpret_cast<uint32_t*>(connection->Buffer) = length | 0x01000000;

		connection->RioBuffer.Offset = 0;
		connection->RioBuffer.Length = length + 4;
		connection->State = ConnectionState::SendingHandshake;
		if (g_rio.RIOSend(connection->RequestQueue, &connection->RioBuffer, 1, 0, 0) == FALSE)
			Fatal("sending handshake failed");
	}
	break;

	case ConnectionState::SendingHandshake:
	{
		connection->RioBuffer.Offset = 0;
		connection->RioBuffer.Length = BufferSize;
		connection->State = ConnectionState::ReceivingAuthOk;
		if (g_rio.RIOReceive(connection->RequestQueue, &connection->RioBuffer, 1, 0, 0) == FALSE)
			Fatal("receiving auth OK failed");
	}
	break;

	case ConnectionState::ReceivingAuthOk:
	{
		PayloadReader reader(connection->Buffer + connection->RioBuffer.Offset, result.BytesTransferred);
		auto header = reader.ReadByte();
		if (header != 0)
			Fatal("couldn't log in");

		goto SendQuery;
	}

	case ConnectionState::SendingQuery:
	{
		connection->RioBuffer.Offset = 0;
		connection->RioBuffer.Length = BufferSize;
		connection->State = ConnectionState::ReceivingResultSet;
		if (g_rio.RIOReceive(connection->RequestQueue, &connection->RioBuffer, 1, 0, 0) == FALSE)
			Fatal("receiving result set failed");
		break;
	}

	case ConnectionState::ReceivingResultSet:
	{
		PayloadReader reader(connection->Buffer + connection->RioBuffer.Offset, result.BytesTransferred);
		InterlockedIncrement(&g_queries);
		goto SendQuery;
	}
	}

	return;

SendQuery:
	uint8_t * output = connection->Buffer;
	*output++ = 53;
	*output++ = 0;
	*output++ = 0;
	*output++ = 0;

	strcpy((char*)output, "\x03SELECT id, randomNumber FROM world WHERE Id =      ;");
	unsigned int value;
	rand_s(&value);
	for (int i = 0; i < 4; i++)
	{
		output[51 - i] = '0' + (value % 10);
		value /= 10;
	}
	connection->RioBuffer.Offset = 0;
	connection->RioBuffer.Length = 57;
	connection->State = ConnectionState::SendingQuery;
	if (g_rio.RIOSend(connection->RequestQueue, &connection->RioBuffer, 1, 0, 0) == FALSE)
		Fatal("Sending query failed");
}


DWORD WINAPI ThreadProc(void *)
{
	while (true)
	{
		DWORD numberOfBytesTransferred;
		ULONG_PTR completionKey;
		OVERLAPPED * overlapped;
		if (GetQueuedCompletionStatus(g_iocp, &numberOfBytesTransferred, &completionKey, &overlapped, INFINITE) != FALSE)
		{
			if (completionKey == 1)
			{
				RIORESULT results[16];
				ULONG numResults = g_rio.RIODequeueCompletion(g_completionQueue, results, 4);

				if (numResults == 0)
					Fatal("RIODequeueCompletion returned 0");
				if (numResults == RIO_CORRUPT_CQ)
					Fatal("RIODequeueCompletion returned RIO_CORRUPT_CQ");

				if (g_rio.RIONotify(g_completionQueue) != ERROR_SUCCESS)
					Fatal("RIONotify failed");				

				for (DWORD i = 0; i < numResults; ++i)
				{
					auto & result = results[i];
					auto connection = reinterpret_cast<Connection *>(result.SocketContext);
					ProcessPacket(connection, result);
				}
			}
		}
		else
		{
			Fatal("GetQueuedCompletionStatus failed");
		}
	}
	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: MySqlBench hostname\n");
		return 2;
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		Fatal("WSAStartup failed");

	struct addrinfo *result = nullptr, hints = { 0 };
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	if (getaddrinfo(argv[1], "3306", &hints, &result) != 0)
		Fatal("getaddrinfo failed");

	g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
	if (g_iocp == nullptr)
		Fatal("CreateIoCompletionPort failed");

	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	for (DWORD i = 0; i < sysinfo.dwNumberOfProcessors; i++)
		CreateThread(nullptr, 0, ThreadProc, (LPVOID) (DWORD_PTR) i, 0, nullptr);

	for (DWORD i = 0; i < sysinfo.dwNumberOfProcessors * 2; i++)
	{
		auto connection = new Connection();
		connection->State = ConnectionState::Initial;

		connection->Socket = ::WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, nullptr, 0, WSA_FLAG_REGISTERED_IO);
		if (connection->Socket == INVALID_SOCKET)
			Fatal("Couldn't create socket");

		if (g_rio.cbSize == 0)
		{
			g_rio.cbSize = sizeof(g_rio);
			GUID functionTableId = WSAID_MULTIPLE_RIO;
			DWORD dwBytes = 0;

			if (WSAIoctl(connection->Socket, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &functionTableId, sizeof(GUID), (void**)&g_rio, g_rio.cbSize, &dwBytes, 0, 0) == SOCKET_ERROR)
				Fatal("Couldn't get RIO functions");

			RIO_NOTIFICATION_COMPLETION type;
			type.Type = RIO_IOCP_COMPLETION;
			type.Iocp.IocpHandle = g_iocp;
			type.Iocp.CompletionKey = (PVOID) 1;
			type.Iocp.Overlapped = &g_overlapped;
			g_completionQueue = g_rio.RIOCreateCompletionQueue(1024, &type);
			if (g_completionQueue == RIO_INVALID_CQ)
				Fatal("Couldn't create completion queue");
		}

		connection->RequestQueue = g_rio.RIOCreateRequestQueue(connection->Socket, 10, 1, 10, 1, g_completionQueue, g_completionQueue, connection);
		if (connection->RequestQueue == RIO_INVALID_RQ)
			Fatal("Couldn't create request queue for socket");

		if (connect(connection->Socket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR)
			Fatal("Couldn't connect socket");

		connection->Buffer = static_cast<uint8_t*>(VirtualAlloc(nullptr, BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		connection->RioBuffer.BufferId = g_rio.RIORegisterBuffer((PCHAR)connection->Buffer, BufferSize);
		connection->RioBuffer.Offset = 0;
		connection->RioBuffer.Length = BufferSize;

		if (g_rio.RIOReceive(connection->RequestQueue, &connection->RioBuffer, 1, 0, 0) == FALSE)
			Fatal("Initial RIOReceive failed");
	}

	if (g_rio.RIONotify(g_completionQueue) != ERROR_SUCCESS)
		Fatal("RIONotify failed");

	for (int i = 0; i < 100; i++)
	{
		LARGE_INTEGER freq, start, stop;
		QueryPerformanceCounter(&start);
		auto queriesStart = g_queries;
		Sleep(1000);
		QueryPerformanceCounter(&stop);
		QueryPerformanceFrequency(&freq);
		auto queriesStop = g_queries;
		auto rps = static_cast<double>(queriesStop - queriesStart) / (static_cast<double>(stop.QuadPart - start.QuadPart) / freq.QuadPart);
		printf("\r%lf req/s   ", rps);
	}

	// no cleanup
	return 0;
}
