#include "ConsoleHost.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ConsoleHostServer.hpp"
#include "TargetProtocol.hpp"
#include "Win32Structure.hpp"
#include "ConsoleEventListener.hpp"
#include "ConsoleInternal.hpp"

//OpenConsole, GetConsoleMode, SetConsoleMode, ReadConsole, WriteConsole, GetConsoleTitle, GetConsoleScreenBufferInfo, GetConsoleLangId, VerifyConsoleIoHandle, GetConsoleCP, SetConsoleTitle
const uint16_t g_csrssAPITableWin7[] = {0, 0x8, 0x11, 0x1d, 0x1e, 0x24, 0xb, 0x4c, 0x23, 0x3c, 0x25};
const uint16_t *g_csrssAPITable;

ConsoleHost::ConsoleHost(ConsoleEventListener *listener) : listener_(listener), lastHandleId_(0)
{	
	if(!g_csrssAPITable)
	{
#ifdef _WIN64
		PEB64 *peb = reinterpret_cast<PEB64 *>(__readgsqword(0x60));
#elif defined(_WIN32)
		PEB32 *peb = reinterpret_cast<PEB32 *>(__readfsdword(0x30));
#endif
		if(peb->OSMajorVersion == 6 && peb->OSMinorVersion == 1)
			g_csrssAPITable = g_csrssAPITableWin7;
	}
	setDefaultMode();
	ConsoleHostServer::registerConsoleHost(this);
}

void ConsoleHost::setDefaultMode()
{
	inputMode_ = ENABLE_ECHO_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE;
	outputMode_ = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
}

void ConsoleHost::startProcess(const std::wstring &cmdline)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_FORCEOFFFEEDBACK;

	CreateProcess(nullptr, const_cast<wchar_t *>(cmdline.c_str()), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
	childProcesses_.push_back(pi.hProcess);

	ConsoleHostServer::patchProcess(pi.hProcess);

	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
}

void ConsoleHost::cleanup()
{
	ConsoleHostServer::unRegisterConsoleHost(this);
	for(auto i : childProcesses_)
	{	
		TerminateProcess(i, 0);
		CloseHandle(i);
	}
}

ConsoleHost::~ConsoleHost()
{
	cleanup();
}

void ConsoleHost::sendNewConsoleAPIResponse(ConsoleHostConnection *connection, void *responsePtr, void *buffer, size_t bufferSize)
{
	WriteProcessMemory(connection->getUserData(), responsePtr, buffer, bufferSize, nullptr);
	connection->sendPacketHeader(HandleDeviceIoControlFile, 0);
}

void ConsoleHost::sendCSRSSConsoleAPIResponse(ConsoleHostConnection *connection, CSRSSLPCMessageHeader *messageHeader)
{
	HandleLPCMessageResponse response;
	response.callOriginal = false;
	connection->sendPacketHeader(HandleLPCMessage, static_cast<uint32_t>(messageHeader->LPCHeader.Length + sizeof(HandleLPCMessageResponse)));
	connection->sendPacketData(&response);
	connection->sendPacketData(reinterpret_cast<const uint8_t *>(messageHeader), messageHeader->LPCHeader.Length);
}

std::vector<uint8_t> ConsoleHost::readCSRSSCaptureData(ConsoleHostConnection *connection, CSRSSLPCMessageHeader *messageHeader)
{
	if(!messageHeader->CsrCaptureData)
		return std::vector<uint8_t>();
	void *ptr = reinterpret_cast<void *>(messageHeader->CsrCaptureData + csrssMemoryDiff_);
	CSR_CAPTURE_BUFFER captureBuffer;
	ReadProcessMemory(connection->getUserData(), ptr, &captureBuffer, sizeof(captureBuffer), nullptr);

	std::vector<uint8_t> result(captureBuffer.Size);
	ReadProcessMemory(connection->getUserData(), ptr, &result[0], captureBuffer.Size, nullptr);

	return result;
}

void ConsoleHost::writeCSRSSCaptureData(ConsoleHostConnection *connection, CSRSSLPCMessageHeader *messageHeader, const std::vector<uint8_t> &buffer)
{
	void *ptr = reinterpret_cast<void *>(messageHeader->CsrCaptureData + csrssMemoryDiff_);

	WriteProcessMemory(connection->getUserData(), ptr, &buffer[0], buffer.size(), nullptr);
}

void *ConsoleHost::getCSRSSCaptureBuffer(ConsoleHostConnection *connection, CSRSSLPCMessageHeader *messageHeader, void *requestPointer, const std::vector<uint8_t> &buffer, int n)
{
	const CSR_CAPTURE_BUFFER *csrBuffer = reinterpret_cast<const CSR_CAPTURE_BUFFER *>(&buffer[0]);
	void *basePointer = reinterpret_cast<void *>(messageHeader->CsrCaptureData);

	ssize_t dataPtr;
	ReadProcessMemory(connection->getUserData(), reinterpret_cast<uint8_t *>(requestPointer) + csrBuffer->PointerOffsetsArray[n], &dataPtr, sizeof(dataPtr), nullptr);
	dataPtr = dataPtr - reinterpret_cast<ssize_t>(basePointer) + reinterpret_cast<ssize_t>(csrBuffer);

	return reinterpret_cast<void *>(dataPtr);
}

void ConsoleHost::handlePacket(ConsoleHostConnection *connection, uint16_t op, uint32_t size, uint8_t *data)
{
	if(op == Initialize)
	{
		InitializeRequest *req = reinterpret_cast<InitializeRequest *>(data);
		InitializeResponse response;

		void *childProcessHandle = nullptr;
		for(auto i : childProcesses_)
			if(GetProcessId(i) == req->pid)
				childProcessHandle = i;

		connection->setUserData(childProcessHandle);

		HANDLE resultHandle;
		DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), childProcessHandle, &resultHandle, 0, TRUE, DUPLICATE_SAME_ACCESS);
		response.parentProcessHandle = reinterpret_cast<uint64_t>(resultHandle);

		connection->sendPacket(Initialize, &response);
	}
	else if(op == HandleCreateFile)
	{
		HandleCreateFileRequest *request = reinterpret_cast<HandleCreateFileRequest *>(data);
		HandleCreateFileResponse response;
		response.returnFake = 1;
		response.fakeHandle = reinterpret_cast<uint64_t>(newFakeHandle());

		wchar_t fileName[255];
		lstrcpyn(fileName, reinterpret_cast<LPCWSTR>(data + sizeof(HandleCreateFileRequest)), request->fileNameLen); //eabuffer follows.
		fileName[request->fileNameLen / 2] = 0;

		if(!wcsncmp(fileName, L"\\Input", 6))
			inputHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));
		else if(!wcsncmp(fileName, L"\\Output", 7))
			outputHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));
		else if(!wcsncmp(fileName, L"\\Device\\ConDrv", 14) || !wcsncmp(fileName, L"\\Reference", 10))
			serverHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));
		else if(!wcsncmp(fileName, L"\\Connect", 8))
		{
			serverHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));
			void *EaBuffer = data + sizeof(HandleCreateFileRequest) + request->fileNameLen;
			//TODO
		}
		else
			response.returnFake = 0;

		connection->sendPacket(HandleCreateFile, &response);
	}
	else if(op == HandleReadFile)
	{
		HandleReadFileRequest *request = reinterpret_cast<HandleReadFileRequest *>(data);

		queueReadOperation(request->sizeToRead, 
						   std::bind(&ConsoleHostConnection::sendPacketWithData, connection, HandleReadFile, std::placeholders::_1, std::placeholders::_2), 
						   false, nullptr);
	}
	else if(op == HandleWriteFile)
	{
		uint8_t *buf = reinterpret_cast<uint8_t *>(data);

		handleWrite(buf, size, false);

		HandleWriteFileResponse response;
		response.writtenSize = size;

		connection->sendPacket(HandleWriteFile, &response);
	}
	else if(op == HandleDeviceIoControlFile)
	{
		HandleDeviceIoControlFileRequest *request = reinterpret_cast<HandleDeviceIoControlFileRequest *>(data);
		uint8_t *inputBuf = data + sizeof(HandleDeviceIoControlFileRequest);

		if(request->code == 0x500037) //Win8.1: Called in ConsoleLaunchServerProcess
		{
			//inputBuf is RTL_USER_PROCESS_PARAMETERS, but we don't use that.
			
			//no output
			connection->sendPacketHeader(HandleDeviceIoControlFile, 0);
		}
		else if(request->code == 0x500023) //Win8.1: Called in ConsoleCommitState
		{
			//kernelbase call SetInformationProcess(ProcessConsoleHostProcess) with result of this ioctl.
			//set outputbuffer to console host process's pid.
			size_t pid = GetCurrentProcessId();
			connection->sendPacket(HandleDeviceIoControlFile, &pid);
		}
		else if(request->code = 0x500016) //Win8.1: Called in ConsoleCallServerGeneric
		{
			//no output

			NewConsoleCallServerRequestData requestData;
			NewConsoleCallServerData *callData = reinterpret_cast<NewConsoleCallServerData *>(inputBuf);
			NewConsoleCallServerGenericData *genericRequest = reinterpret_cast<NewConsoleCallServerGenericData *>(inputBuf + sizeof(NewConsoleCallServerData));
			ReadProcessMemory(connection->getUserData(), reinterpret_cast<LPCVOID>(callData->requestDataPtr), &requestData, sizeof(NewConsoleCallServerRequestData), nullptr);

			if(requestData.requestCode == 0x1000008) //SetTEBLangID
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, 0);
			else if(requestData.requestCode == 0x1000000) //GetConsoleCP
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, CP_UTF8);
			else if(requestData.requestCode == 0x1000002) //SetConsoleMode
			{
				setConsoleMode(callData->requestHandle, requestData.data);
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, 0);
			}
			else if(requestData.requestCode == 0x1000001) //GetConsoleMode
			{
				uint32_t result = getConsoleMode(callData->requestHandle);
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, result);
			}
			else if(requestData.requestCode == 0x2000014) //GetConsoleTitle
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, 0);
			else if(requestData.requestCode == 0x2000007) //GetConsoleScreenBufferInfoEx
			{
				GetConsoleScreenBufferInfoExResponse response;
				getConsoleScreenBufferInfo(&response);
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, &response, sizeof(response));
			}
			else if(requestData.requestCode == 0x1000006) //WriteConsole
			{
				NewWriteConsoleRequestData *request = reinterpret_cast<NewWriteConsoleRequestData *>(inputBuf + sizeof(NewConsoleCallServerData));
				uint8_t *writeData = new uint8_t[request->dataSize];
				ReadProcessMemory(connection->getUserData(), reinterpret_cast<LPCVOID>(request->dataPtr), writeData, request->dataSize, nullptr);

				handleWrite(writeData, request->dataSize, (requestData.data1 == 1));

				delete [] writeData;

				sendNewConsoleAPIResponse(connection, request->responsePtr, request->dataSize);
			}
			else if(requestData.requestCode == 0x1000005) //ReadConsole
			{
				NewReadConsoleRequestData *request = reinterpret_cast<NewReadConsoleRequestData *>(inputBuf + sizeof(NewConsoleCallServerData));

				struct ReadConsoleData
				{
					void *responsePtr;
					void *dataPtr;
					ConsoleHostConnection *connection;
				};
				ReadConsoleData *userData = new ReadConsoleData;
				userData->responsePtr = request->responsePtr;
				userData->dataPtr = request->dataPtr;
				userData->connection = connection;

				queueReadOperation(request->sizeToRead, [this](const uint8_t *buffer, size_t bufferSize, size_t nChar, void *userData) {
					ReadConsoleData *readData = reinterpret_cast<ReadConsoleData *>(userData);

					WriteProcessMemory(readData->connection->getUserData(), readData->dataPtr, buffer, bufferSize, nullptr);
					sendNewConsoleAPIResponse(readData->connection, readData->responsePtr, static_cast<uint32_t>(nChar));

					delete readData;
				}
				, ((requestData.data && 0xff) == 1), userData);
			}
			else if(requestData.requestCode == 0x0200000a) //SetConsoleCursorPosition
				sendNewConsoleAPIResponse(connection, genericRequest->responsePtr, 0);
			else
				__nop();
		}
		else
			__debugbreak();
	}
	else if(op == HandleCreateUserProcess)
	{
		HandleCreateUserProcessRequest *request = reinterpret_cast<HandleCreateUserProcessRequest *>(data);

		if(ConsoleHostServer::patchProcess(reinterpret_cast<void *>(request->processHandle)))
		{
			childProcesses_.push_back(reinterpret_cast<void *>(request->processHandle));
			ConsoleHostServer::registerConsoleHost(this);
		}
		
		connection->sendPacketHeader(HandleCreateUserProcess, 0);
	}
	else if(op == HandleLPCMessage)
	{
		HandleLPCMessageRequest *request = reinterpret_cast<HandleLPCMessageRequest *>(data);

		bool sent = false;
		if(g_csrssAPITable)
		{
			sent = true;

			CSRSSLPCMessageHeader *messageHeader = reinterpret_cast<CSRSSLPCMessageHeader *>(data + sizeof(HandleLPCMessageRequest));
			uint8_t *dataPtr = data + sizeof(HandleLPCMessageRequest)+ sizeof(CSRSSLPCMessageHeader);
			uint32_t apiNumber = messageHeader->ApiNumber & 0xffffffff;
			if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiOpenConsole])	//kernel32 initialize always tries to openconsole first.
			{																//calling original will fail(no existing console), so our console will work.
				HandleLPCMessageResponse response;
				response.callOriginal = true;
				connection->sendPacket(HandleLPCMessage, &response);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiGetConsoleMode])
			{
				CSRSSGetSetConsoleModeData *rdata = reinterpret_cast<CSRSSGetSetConsoleModeData *>(dataPtr);
				rdata->mode = getConsoleMode(rdata->handle);
			
				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiSetConsoleMode])
			{
				CSRSSGetSetConsoleModeData *rdata = reinterpret_cast<CSRSSGetSetConsoleModeData *>(dataPtr);
				setConsoleMode(rdata->handle, rdata->mode);

				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiReadConsole])
			{
				struct CSRSSReadLambdaData
				{
					std::vector<uint8_t> messageBuf;
					std::vector<uint8_t> captureBuffer;
					void *requestPointer;
					ConsoleHostConnection *connection;
				};
				CSRSSReadLambdaData *userData = new CSRSSReadLambdaData;
				userData->messageBuf.assign(data, data + size);
				userData->captureBuffer = readCSRSSCaptureData(connection, messageHeader);
				userData->requestPointer = reinterpret_cast<void *>(request->requestPointer);
				userData->connection = connection;

				CSRSSReadConsoleData *readData = reinterpret_cast<CSRSSReadConsoleData *>(dataPtr);

				queueReadOperation(readData->sizeToRead, [this](const uint8_t *buffer, size_t bufferSize, size_t nChar, void *userData) {
					CSRSSReadLambdaData *readLambdaData = reinterpret_cast<CSRSSReadLambdaData *>(userData);
					uint8_t *data = &readLambdaData->messageBuf[0];
					CSRSSLPCMessageHeader *messageHeader = reinterpret_cast<CSRSSLPCMessageHeader *>(data + sizeof(HandleLPCMessageRequest));
					uint8_t *dataPtr = data + sizeof(HandleLPCMessageRequest) + sizeof(CSRSSLPCMessageHeader);
					CSRSSReadConsoleData *readData = reinterpret_cast<CSRSSReadConsoleData *>(dataPtr);

					if(messageHeader->CsrCaptureData)
					{
						uint8_t *data = reinterpret_cast<uint8_t *>(getCSRSSCaptureBuffer(readLambdaData->connection, messageHeader, 
							readLambdaData->requestPointer, readLambdaData->captureBuffer, 0));
						memcpy(data, buffer, bufferSize);
						writeCSRSSCaptureData(readLambdaData->connection, messageHeader, readLambdaData->captureBuffer);
					}
					else
						memcpy(readData->data, buffer, bufferSize);
					readData->sizeRead = static_cast<uint32_t>(bufferSize);

					messageHeader->Status = 0;
					sendCSRSSConsoleAPIResponse(readLambdaData->connection, messageHeader);

					delete readLambdaData;
				}, readData->isWideChar == 1, userData);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiWriteConsole])
			{
				CSRSSWriteConsoleData *writeData = reinterpret_cast<CSRSSWriteConsoleData *>(dataPtr);
				if(writeData->isEmbedded == 1)
					handleWrite(writeData->data, writeData->dataSize, writeData->isWideChar == 1);
				else
				{
					std::vector<uint8_t> buffer = readCSRSSCaptureData(connection, messageHeader);
					uint8_t *data = reinterpret_cast<uint8_t *>(getCSRSSCaptureBuffer(connection, messageHeader, reinterpret_cast<void *>(request->requestPointer), buffer, 0));
					handleWrite(data, writeData->dataSize, writeData->isWideChar == 1);
				}
				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiGetConsoleTitle])
			{
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiGetConsoleScreenBufferInfo])
			{
				CSRSSGetConsoleScreenBufferInfoExResponse *data = reinterpret_cast<CSRSSGetConsoleScreenBufferInfoExResponse *>(dataPtr);
				getConsoleScreenBufferInfo(&data->data);

				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiGetConsoleLangId])
			{
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiVerifyConsoleIoHandle])
			{
				CSRSSVerifyConsoleIoHandleData *data = reinterpret_cast<CSRSSVerifyConsoleIoHandleData *>(dataPtr);

				data->result = 1;
				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiGetConsoleCP])
			{
				CSRSSGetSetCPData *rdata = reinterpret_cast<CSRSSGetSetCPData *>(dataPtr);
				rdata->codepage = CP_UTF8;
				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == g_csrssAPITable[CSRSSAPI::CSRSSApiSetConsoleTitle])
			{
				messageHeader->Status = 0;
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else if(apiNumber == 0x53) //only in windows 7. ConsoleClientConnect
			{
				std::vector<uint8_t> buffer = readCSRSSCaptureData(connection, messageHeader);

				CSRSSConsoleClientConnectData *connectData = reinterpret_cast<CSRSSConsoleClientConnectData *>(
					getCSRSSCaptureBuffer(connection, messageHeader, reinterpret_cast<void *>(request->requestPointer), buffer, 0));

				connectData->consoleHandle = newFakeHandle();
				connectData->inputHandle = newFakeHandle();
				connectData->outputHandle = newFakeHandle();
				connectData->errorHandle = newFakeHandle();

				serverHandles_.push_back(connectData->consoleHandle);
				inputHandles_.push_back(connectData->inputHandle);
				outputHandles_.push_back(connectData->outputHandle);
				outputHandles_.push_back(connectData->errorHandle);

				messageHeader->Status = 0;
				writeCSRSSCaptureData(connection, messageHeader, buffer);
				sendCSRSSConsoleAPIResponse(connection, messageHeader);
			}
			else
				sent = false;
		}
		if(sent == false)
		{
			HandleLPCMessageResponse response;
			response.callOriginal = true;
			connection->sendPacket(HandleLPCMessage, &response);
		}
	}
	else if(op == HandleLPCConnect)
	{
		LPCConnectRequest *request = reinterpret_cast<LPCConnectRequest *>(data);
		csrssMemoryDiff_ = -static_cast<ssize_t>(request->serverBase) + static_cast<ssize_t>(request->clientBase);
		connection->sendPacketHeader(HandleLPCConnect, 0);
	}
	else if(op == HandleDuplicateObject)
	{
		HandleDuplicateObjectRequest *request = reinterpret_cast<HandleDuplicateObjectRequest *>(data);

		HandleDuplicateObjectResponse response;
		response.fakeHandle = reinterpret_cast<uint64_t>(newFakeHandle());

		if(isOutputHandle(reinterpret_cast<void *>(request->handle)))
			outputHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));
		else if(isInputHandle(reinterpret_cast<void *>(request->handle)))
			inputHandles_.push_back(reinterpret_cast<void *>(response.fakeHandle));

		connection->sendPacket(HandleDuplicateObject, &response);
	}
}

void *ConsoleHost::newFakeHandle()
{
	return reinterpret_cast<void *>((0x6eff00f3 | ((lastHandleId_ ++) << 8)));
}

void ConsoleHost::getConsoleScreenBufferInfo(GetConsoleScreenBufferInfoExResponse *response)
{
	ZeroMemory(response, sizeof(GetConsoleScreenBufferInfoExResponse));
	response->size.X = 80;
	response->size.Y = 24;
}

bool ConsoleHost::isInputHandle(void *handle)
{
	for(auto &i : inputHandles_)
		if(i == handle)
			return true;
	return false;
}

bool ConsoleHost::isOutputHandle(void *handle)
{
	for(auto &i : outputHandles_)
		if(i == handle)
			return true;
	return false;
}

void ConsoleHost::handleDisconnected()
{

}

void ConsoleHost::write(const std::wstring &buffer)
{
	if(!queuedReadOperations_.size())
		return;

	auto i = queuedReadOperations_.front();

	if(i.isWideChar == false)
	{
		char *buf;
		int len;

		len = WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, nullptr, 0, 0, 0);
		buf = new char[len];
		WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, buf, len, 0, 0);
		buf[len - 1] = 0;

		i.completionHandler(reinterpret_cast<const uint8_t *>(buf), len, len - 1, i.userData);
		delete[] buf;
	}
	else
		i.completionHandler(reinterpret_cast<const uint8_t *>(buffer.c_str()), buffer.size() * 2, buffer.size() - 1, i.userData);
	queuedReadOperations_.pop();
}

void ConsoleHost::queueReadOperation(size_t size, const std::function<void (const uint8_t *, size_t, size_t, void *)> &completionHandler, bool isWideChar, void *userData)
{
	ConsoleReadOperation operation;
	operation.size = size;
	operation.completionHandler = completionHandler;
	operation.isWideChar = isWideChar;
	operation.userData = userData;
	queuedReadOperations_.push(operation);

	listener_->handleRead(size);
}

void ConsoleHost::handleWrite(uint8_t *buffer, size_t bufferSize, bool isWideChar)
{
	std::wstring stringBuf;
	if(!isWideChar)
	{
		//input is unicode
		int size = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPSTR>(buffer), static_cast<int>(bufferSize), nullptr, 0);
		stringBuf.resize(size);
		MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<LPSTR>(buffer), static_cast<int>(bufferSize), reinterpret_cast<LPTSTR>(&stringBuf[0]), size);
	}
	else
		stringBuf.assign(reinterpret_cast<wchar_t *>(buffer), reinterpret_cast<wchar_t *>(buffer) + bufferSize / 2);
	listener_->handleWrite(stringBuf);
}

uint32_t ConsoleHost::getConsoleMode(void *handle)
{
	if(isInputHandle(handle))
		return inputMode_;
	else if(isOutputHandle(handle))
		return outputMode_;
	else
		return 0;
}

void ConsoleHost::setConsoleMode(void *handle, uint32_t mode)
{
	if(isInputHandle(handle))
		inputMode_ = mode;
	else if(isOutputHandle(handle))
		outputMode_ = mode;
}

uint32_t ConsoleHost::getInputMode()
{
	return inputMode_;
}