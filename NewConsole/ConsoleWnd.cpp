#include "ConsoleWnd.h"

#include "ConsoleHost.h"
#include "NewConsole.h"

ConsoleWnd::ConsoleWnd(const std::wstring &cmdline, std::weak_ptr<NewConsole> mainWnd) : 
	cacheWidth_(-1), cacheHeight_(-1), mainWnd_(mainWnd), cacheScrollx_(-1), cacheScrolly_(-1)
{
	host_.reset(new ConsoleHost(cmdline, this));
}

ConsoleWnd::~ConsoleWnd()
{
}

void ConsoleWnd::appendStringToBuffer(const std::wstring &buffer)
{
	std::lock_guard<std::mutex> guard(bufferLock_);
	std::wstring line;
	if(lastLine_.size())
	{
		line = lastLine_;
		buffer_.pop_back();
	}
	size_t pos = line.size();
	for(size_t i = 0; i < buffer.size(); i ++)
	{
		if(buffer[i] == '\n')
		{
			buffer_.push_back(std::make_pair(line, 0.f));

			line.clear();
			pos = 0;
		}
		else if(buffer[i] == '\r')
			pos = 0;
		else
		{
			if(pos + 1 > line.size())
				line.push_back(buffer[i]);
			else
				line[pos] = buffer[i];
			pos ++;
		}
	}
	if(line.size())
	{
		buffer_.push_back(std::make_pair(line, 0.f));
		lastLine_ = line;
	}
	else
		lastLine_.clear();
	bufferUpdated();
}

void ConsoleWnd::handleWrite(const std::string &buffer)
{
	std::wstring wideBuffer;
	int len = MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), -1, nullptr, 0);
	wideBuffer.resize(len - 1);
	MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), -1, &wideBuffer[0], len);

	appendStringToBuffer(wideBuffer);
}

void ConsoleWnd::updateCache(int width, int height, int scrollx, int scrolly)
{
	if(cacheWidth_ != width || cacheHeight_ != height)
	{
		cacheBitmap_.reset(new Gdiplus::Bitmap(width, height, PixelFormat32bppARGB));
		cacheWidth_ = width;
		cacheHeight_ = height;
	}

	Gdiplus::Graphics g(cacheBitmap_.get());
	Gdiplus::Font font(L"Consolas", 10);
	Gdiplus::SolidBrush blackBrush(Gdiplus::Color::Black);
	Gdiplus::SolidBrush whiteBrush(Gdiplus::Color::White);
	Gdiplus::RectF screen(0.f, 0.f, static_cast<float>(width), static_cast<float>(height));
	Gdiplus::StringFormat format(Gdiplus::StringFormatFlagsBypassGDI);
	g.FillRectangle(&blackBrush, 0, 0, width, height);

	std::lock_guard<std::mutex> guard(bufferLock_);
	float currentHeight = 0;
	decltype(buffer_)::reverse_iterator it;
	for(it = buffer_.rbegin(); it != buffer_.rend(); ++ it)
	{
		if(it->second == 0.f)
		{
			std::wstring string = it->first;
			if(string.size() == 0) //empty line
				string = L"\r\n";
			Gdiplus::RectF bound;
			g.MeasureString(string.c_str(), static_cast<int>(string.size()), &font, screen, &format, &bound);
			it->second = bound.Height;
		}
		currentHeight += it->second;

		if(currentHeight > screen.Height)
			break;
	}
	while(true)
	{
		-- it;
		g.DrawString(it->first.c_str(), static_cast<int>(it->first.size()), &font, screen, &format, &whiteBrush);
		screen.Y += it->second;

		if(it == buffer_.rbegin())
			break;
	}
}

void ConsoleWnd::drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly)
{
	if(scrolly != cacheScrolly_ || scrollx != cacheScrollx_ || width != cacheWidth_ || height != cacheHeight_)
		updateCache(width, height, scrollx, scrolly);

	Gdiplus::Graphics g(hdc);
	g.DrawImage(cacheBitmap_.get(), x, y);
}

void ConsoleWnd::appendInputBuffer(const std::wstring &buffer)
{
	std::string utf8Buffer;
	int len = WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, nullptr, 0, 0, nullptr);
	utf8Buffer.resize(len - 1);
	WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), -1, &utf8Buffer[0], len, 0, nullptr);

	size_t pos = utf8Buffer.find('\n');
	while(pos != std::string::npos)
	{
		if(!(pos > 0 && utf8Buffer[pos - 1] == '\r'))
			utf8Buffer.insert(pos, "\r");
		pos = utf8Buffer.find('\n', pos + 2);
	}
	host_->write(utf8Buffer);
}

void ConsoleWnd::bufferUpdated()
{
	invalidateCache();
	if(!mainWnd_.expired())
		mainWnd_.lock()->contentsUpdated(shared_from_this());
}

void ConsoleWnd::invalidateCache()
{
	cacheScrollx_ = -1;
}