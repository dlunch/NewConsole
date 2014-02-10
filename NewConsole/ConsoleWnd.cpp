#include "ConsoleWnd.hpp"

#include "ConsoleHost.hpp"
#include "NewConsole.hpp"

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
	auto lastLine = buffer_.end();
	if(buffer_.size() == 0)
	{
		std::lock_guard<std::mutex> guard(bufferLock_);
		lastLine = buffer_.insert(buffer_.end(), std::make_pair(std::wstring(L""), 0.f));
	}
	else
		lastLine --;
	std::wstring *line = &lastLine->first; //we need to modify last line.
	size_t pos = line->size();
	for(size_t i = 0; i < buffer.size(); i ++)
	{
		if(buffer[i] == '\n')
		{
			std::lock_guard<std::mutex> guard(bufferLock_);
			auto it = buffer_.insert(buffer_.end(), std::make_pair(std::wstring(L""), 0.f));
			line = &it->first;
			pos = 0;
		}
		else if(buffer[i] == '\r')
			pos = 0;
		else
		{
			if(pos + 1 > line->size())
				line->push_back(buffer[i]);
			else
				(*line)[pos] = buffer[i];
			pos ++;
		}
	}
	bufferUpdated();
}

void ConsoleWnd::handleWrite(const std::wstring &buffer)
{
	appendStringToBuffer(buffer);
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

	float currentHeight = 0;
	decltype(buffer_)::reverse_iterator it, begin, end;
	{
		std::lock_guard<std::mutex> guard(bufferLock_);

		begin = buffer_.rbegin();
		end = buffer_.rend();
		for(it = begin; it != end; ++ it)
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
			if(it == begin && (host_->getInputMode() & ENABLE_ECHO_INPUT))
			{
				std::wstring tmp = it->first + inputBuffer_;
				g.DrawString(tmp.c_str(), static_cast<int>(tmp.size()), &font, screen, &format, &whiteBrush);
			}
			else
				g.DrawString(it->first.c_str(), static_cast<int>(it->first.size()), &font, screen, &format, &whiteBrush);
			
			screen.Y += it->second;

			if(it == begin)
				break;
		}
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
	if(!(host_->getInputMode() & ENABLE_LINE_INPUT))
	{
		host_->write(buffer);
		return;
	}
	std::wstring buf;
	size_t end = buffer.find(L'\n');
	size_t start = 0;
	if(end == std::string::npos)
		buf = buffer;
	else
	{
		while(end != std::wstring::npos)
		{
			buf = inputBuffer_;
			buf.append(buffer.begin() + start, buffer.begin() + end);
			buf.append(L"\r\n");
			inputBuffer_.clear();
			host_->write(buf);
			appendStringToBuffer(buf);

			start = end + 1;
			end = buffer.find(L'\n', start);
		}
		buf = buffer.substr(start);
	}

	inputBuffer_ += buf;
	if(host_->getInputMode() & ENABLE_ECHO_INPUT)
		bufferUpdated();
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