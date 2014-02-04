#include "ConsoleHost.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "ConsoleHostServer.h"
#include "TargetProtocol.h"
#include "Win32Structure.h"
#include "ConsoleEventListener.h"

ConsoleHost::ConsoleHost(const std::wstring &cmdline, ConsoleEventListener *listener) : listener_(listener), lastHandleId_(0)
{
	try
	{
		ConsoleHostServer::registerConsoleHost(this);
		
		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_FORCEOFFFEEDBACK;

		CreateProcess(nullptr, const_cast<wchar_t *>(cmdline.c_str()), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
		childProcess_ = pi.hProcess;
		childProcessId_ = pi.dwProcessId;

		ConsoleHostServer::patchProcess(pi.hProcess);

		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);

		//default mode
		inputMode_ = ENABLE_ECHO_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE;
		outputMode_ = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
	}
	catch(...)
	{
		cleanup();
		throw;
	}
}

void ConsoleHost::cleanup()
{
	ConsoleHostServer::unRegisterConsoleHost(this);
	TerminateProcess(childProcess_, 0);
	CloseHandle(childProcess_);
}

ConsoleHost::~ConsoleHost()
{
	cleanup();
}

void ConsoleHost::handlePacket(uint16_t op, uint32_t size, uint8_t *data)
{
	if(op == Initialize)
	{
		InitializeRequest *req = reinterpret_cast<InitializeRequest *>(data);
		InitializeResponse response;

		HANDLE resultHandle;
		DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), childProcess_, &resultHandle, 0, TRUE, DUPLICATE_SAME_ACCESS);
		response.parentProcessHandle = reinterpret_cast<uint64_t>(resultHandle);

		connection_->sendPacket(Initialize, &response);
	}
	else if(op == HandleCreateFile)
	{
		HandleCreateFileRequest *request = reinterpret_cast<HandleCreateFileRequest *>(data);
		HandleCreateFileResponse response;
		response.returnFake = true;
		response.fakeHandle = newFakeHandle();

		wchar_t fileName[255];
		lstrcpyn(fileName, reinterpret_cast<LPCWSTR>(data + sizeof(HandleCreateFileRequest)), request->fileNameLen); //eabuffer follows.
		fileName[request->fileNameLen / 2] = 0;

		if(!wcsncmp(fileName, L"\\Input", 6))
			inputHandles_.push_back(response.fakeHandle);
		else if(!wcsncmp(fileName, L"\\Output", 7))
			outputHandles_.push_back(response.fakeHandle);
		else if(!wcsncmp(fileName, L"\\Device\\ConDrv", 14) || !wcsncmp(fileName, L"\\Reference", 10))
			serverHandles_.push_back(response.fakeHandle);
		else if(!wcsncmp(fileName, L"\\Connect", 8))
		{
			serverHandles_.push_back(response.fakeHandle);
			void *EaBuffer = data + sizeof(HandleCreateFileRequest) + request->fileNameLen;
			//TODO
		}
		else
			response.returnFake = false;

		connection_->sendPacket(HandleCreateFile, &response);
	}
	else if(op == HandleReadFile)
	{
		HandleReadFileRequest *request = reinterpret_cast<HandleReadFileRequest *>(data);

		queueReadOperation(request->readSize, 
						   std::bind(&ConsoleHostConnection::sendPacketWithData, connection_, HandleReadFile, std::placeholders::_1, std::placeholders::_2), 
						   false, nullptr);
	}
	else if(op == HandleWriteFile)
	{
		uint8_t *buf = reinterpret_cast<uint8_t *>(data);

		handleWrite(buf, size);

		HandleWriteFileResponse response;
		response.writtenSize = size;

		connection_->sendPacket(HandleWriteFile, &response);
	}
	else if(op == HandleDeviceIoControlFile)
	{
		HandleDeviceIoControlFileRequest *request = reinterpret_cast<HandleDeviceIoControlFileRequest *>(data);
		uint8_t *inputBuf = data + sizeof(HandleDeviceIoControlFileRequest);

		if(request->code == 0x500037) //Win8.1: Called in ConsoleLaunchServerProcess
		{
			//inputBuf is RTL_USER_PROCESS_PARAMETERS, but we don't use that.
			
			//no output
			connection_->sendPacket(HandleDeviceIoControlFile);
		}
		else if(request->code == 0x500023) //Win8.1: Called in ConsoleCommitState
		{
			//kernelbase call SetInformationProcess(ProcessConsoleHostProcess) with result of this ioctl.
			//set outputbuffer to console host process's pid.
			size_t pid = GetCurrentProcessId();
			connection_->sendPacket(HandleDeviceIoControlFile, &pid);
		}
		else if(request->code = 0x500016) //Win8.1: Called in ConsoleCallServerGeneric
		{
			//no output
#pragma pack(push, 4)
			struct ConsoleCallServerData
			{
				void *requestHandle;
				uint32_t unk1;
				uint32_t unk2;
				uint32_t unk3;
				uint32_t unk4;
				void *requestDataPtr;
			};

			struct ConsoleCallServerGenericData
			{
				uint32_t unk1;
				uint32_t unk2;
				void *responsePtr;
			};

			struct ConsoleCallServerRequestData
			{
				uint32_t requestCode;
				uint32_t unk;
				uint32_t data;
			};
			struct WriteConsoleRequestData
			{
				uint32_t dataSize;
				uint32_t unk;
				void *dataPtr;
				uint32_t unk1;
				uint32_t unk2;
				void *responsePtr;
			};
			struct ReadConsoleRequestData
			{
				uint32_t unk1;
				uint32_t unk2;
				void *unkPtr;
				uint32_t unk3;
				uint32_t unk4;
				void *dataPtr2;
				uint32_t unk5;
				uint32_t unk6;
				void *responsePtr;
				uint32_t readSize;
				uint32_t unk7;
				void *dataPtr;
			};
#pragma pack(pop)

			ConsoleCallServerRequestData requestData;
			ConsoleCallServerData *callData = reinterpret_cast<ConsoleCallServerData *>(inputBuf);
			ReadProcessMemory(childProcess_, reinterpret_cast<LPCVOID>(callData->requestDataPtr), &requestData, sizeof(ConsoleCallServerRequestData), nullptr);
			uint32_t result = 0;
			void *responsePtr = nullptr;
			bool noresult = false;

			if(requestData.requestCode == 0x1000008) //SetTEBLangID
				result = 0;
			else if(requestData.requestCode == 0x1000000) //GetConsoleCP
				result = CP_UTF8;
			else if(requestData.requestCode == 0x1000002) //SetConsoleMode
			{
				if(isInputHandle(callData->requestHandle))
					inputMode_ = requestData.data;
				else if(isOutputHandle(callData->requestHandle))
					outputMode_ = requestData.data;
				result = 0;
			}
			else if(requestData.requestCode == 0x1000001) //GetConsoleMode
			{
				if(isInputHandle(callData->requestHandle))
					result = inputMode_;
				else if(isOutputHandle(callData->requestHandle))
					result = outputMode_;
				else
					result = 0;
			}
			else if(requestData.requestCode == 0x2000014) //GetConsoleTitle
				__nop();
			else if(requestData.requestCode == 0x2000007) //GetConsoleScreenBufferInfoEx
			{
				struct ResponseStruct
				{
					uint32_t unk;
					uint32_t unk1;
					COORD size;
					COORD cursorPos;
				};
				noresult = true;
				ResponseStruct response;
				ZeroMemory(&response, sizeof(response));
				response.size.X = 80;
				response.size.Y = 24;
				WriteProcessMemory(childProcess_, responsePtr, &response, sizeof(response), nullptr);
				connection_->sendPacket(HandleDeviceIoControlFile);
			}
			else if(requestData.requestCode == 0x1000006) //WriteConsole
			{
				WriteConsoleRequestData *request = reinterpret_cast<WriteConsoleRequestData *>(inputBuf + sizeof(ConsoleCallServerData));
				uint8_t *writeData = new uint8_t[request->dataSize];
				ReadProcessMemory(childProcess_, reinterpret_cast<LPCVOID>(request->dataPtr), writeData, request->dataSize, nullptr);

				if(requestData.data)
				{
					//input is unicode
					int size = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(writeData), request->dataSize / 2, nullptr, 0, 0, nullptr);
					uint8_t *utf8Data = new uint8_t[size + 1];
					WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(writeData), -1, reinterpret_cast<LPSTR>(utf8Data), size, 0, nullptr);

					handleWrite(utf8Data, size);
				}
				else
					handleWrite(writeData, request->dataSize);

				delete [] writeData;

				result = static_cast<uint32_t>(request->dataSize);
				responsePtr = request->responsePtr;
			}
			else if(requestData.requestCode == 0x1000005) //ReadConsole
			{
				ReadConsoleRequestData *request = reinterpret_cast<ReadConsoleRequestData *>(inputBuf + sizeof(ConsoleCallServerData));
				noresult = true;

				struct ReadConsoleData
				{
					void *responsePtr;
					void *dataPtr;
				};
				ReadConsoleData *userData = new ReadConsoleData;
				userData->responsePtr = request->responsePtr;
				userData->dataPtr = request->dataPtr;

				queueReadOperation(request->readSize, [this](const uint8_t *buffer, size_t bufferSize, size_t nChar, void *userData) {
					ReadConsoleData *readData = reinterpret_cast<ReadConsoleData *>(userData);

					WriteProcessMemory(childProcess_, readData->dataPtr, buffer, bufferSize, nullptr);
					WriteProcessMemory(childProcess_, readData->responsePtr, &nChar, sizeof(uint32_t), nullptr);
					connection_->sendPacket(HandleDeviceIoControlFile);

					delete readData;
				}
				, (requestData.data > 0), userData);
			}
			else
				__nop();

			if(!noresult)
			{
				if(!responsePtr)
				{
					ConsoleCallServerGenericData *request = reinterpret_cast<ConsoleCallServerGenericData *>(inputBuf + sizeof(ConsoleCallServerData));
					responsePtr = request->responsePtr;
				}

				WriteProcessMemory(childProcess_, responsePtr, &result, sizeof(uint32_t), nullptr);
				connection_->sendPacket(HandleDeviceIoControlFile);
			}
		}
		else
			__debugbreak();
	}
	else if(op == HandleCreateUserProcess)
	{
		HandleCreateUserProcessRequest *request = reinterpret_cast<HandleCreateUserProcessRequest *>(data);

		ConsoleHostServer::patchProcess(request->processHandle);
		
		connection_->sendPacket(HandleCreateUserProcess);
	}
	else if(op == HandleLPCMessage)
	{
		LPC_MESSAGE *lpcHeader = reinterpret_cast<LPC_MESSAGE *>(data);

		struct ConsoleAPIMessageHeader
		{
			size_t CsrCaptureData;
			size_t ApiNumber;
			uint32_t Status;
			uint32_t Reserved;
		};

		ConsoleAPIMessageHeader *messageHeader = reinterpret_cast<ConsoleAPIMessageHeader *>(data + sizeof(LPC_MESSAGE));

		HandleLPCMessageResponse response;
		response.callOriginal = true;
		connection_->sendPacket(HandleLPCMessage, &response);
	}
	else if(op == HandleDuplicateObject)
	{
		HandleDuplicateObjectRequest *request = reinterpret_cast<HandleDuplicateObjectRequest *>(data);

		HandleDuplicateObjectResponse response;
		response.fakeHandle = newFakeHandle();

		if(isOutputHandle(request->handle))
			outputHandles_.push_back(response.fakeHandle);
		else if(isInputHandle(request->handle))
			inputHandles_.push_back(response.fakeHandle);

		connection_->sendPacket(HandleDuplicateObject, &response);
	}
}

void *ConsoleHost::newFakeHandle()
{
	return reinterpret_cast<void *>((0xeeff00f3 | ((lastHandleId_ ++) << 8)));
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

void ConsoleHost::write(const std::string &buffer)
{
	inputBuffer_ += buffer;

	if(inputMode_ & ENABLE_ECHO_INPUT)
		listener_->handleWrite(buffer);
	checkQueuedRead();
}

void ConsoleHost::queueReadOperation(size_t size, const std::function<void (const uint8_t *, size_t, size_t, void *)> &completion, bool isWidechar, void *userData)
{
	queuedReadOperations_.push_back(std::make_tuple(size, completion, isWidechar, userData));
	checkQueuedRead();
}

void ConsoleHost::checkQueuedRead()
{
	while(queuedReadOperations_.size())
	{
		auto &i = queuedReadOperations_.front();
		if(inputMode_ & ENABLE_LINE_INPUT)
		{
			size_t newlineOff = inputBuffer_.find("\r\n");
			if(newlineOff == std::string::npos)
				break;
			newlineOff += 2;
			std::string buffer(inputBuffer_.begin(), inputBuffer_.begin() + newlineOff);
			inputBuffer_.erase(0, newlineOff);

			if(std::get<2>(i) == true)
			{
				wchar_t *buf;
				int len;

				len = MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), -1, nullptr, 0);
				buf = new wchar_t[len];
				MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), -1, buf, len);
				buf[len - 1] = 0;

				std::get<1>(i)(reinterpret_cast<const uint8_t *>(buf), (len - 1) * 2, len - 1, std::get<3>(i));
				delete [] buf;
			}
			else
				std::get<1>(i)(reinterpret_cast<const uint8_t *>(buffer.c_str()), buffer.size(), buffer.size(), std::get<3>(i));

			queuedReadOperations_.pop_front();
		}
	}
}

void ConsoleHost::handleWrite(uint8_t *buffer, size_t bufferSize)
{
	listener_->handleWrite(std::string(buffer, buffer + bufferSize));
}

void ConsoleHost::setConnection(ConsoleHostConnection *connection)
{
	connection_ = connection;
}