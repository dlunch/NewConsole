#include "ConsoleWnd.hpp"

#include "ConsoleHost.hpp"
#include "NewConsole.hpp"

#undef min
#undef max

ITfThreadMgr *ConsoleWnd::tsfThreadMgr_;
TfClientId ConsoleWnd::tsfClientId_;

ConsoleWnd::ConsoleWnd(const std::wstring &cmdline, std::weak_ptr<NewConsole> mainWnd) : 
	cacheWidth_(-1), cacheHeight_(-1), mainWnd_(mainWnd), cacheScrollx_(-1), cacheScrolly_(-1),
	tsfDocumentMgr_(nullptr), tsfContext_(nullptr), tsfACPSink_(nullptr), 
	selStart_(0), selEnd_(0), isSelectionInterim_(false), isSelectionEndsAtLeft_(false),
	currentReadSize_(0)
{
	if(!tsfThreadMgr_)
	{
		HRESULT hr = CoCreateInstance(CLSID_TF_ThreadMgr, 0, CLSCTX_INPROC_SERVER, IID_ITfThreadMgr, reinterpret_cast<void **>(&tsfThreadMgr_));
		tsfThreadMgr_->Activate(&tsfClientId_);
	}

	tsfThreadMgr_->CreateDocumentMgr(&tsfDocumentMgr_);

	IUnknown *thisUnknown;
	QueryInterface(IID_IUnknown, reinterpret_cast<void **>(&thisUnknown));
	tsfDocumentMgr_->CreateContext(tsfClientId_, 0, thisUnknown, &tsfContext_, &tsfEditCookie_);
	tsfDocumentMgr_->Push(tsfContext_);

	host_.reset(new ConsoleHost(this));
	host_->startProcess(cmdline);
}

ConsoleWnd::~ConsoleWnd()
{
	if(tsfACPSink_)
		tsfACPSink_->Release();
	if(tsfContext_)
		tsfContext_->Release();
	if(tsfDocumentMgr_)
		tsfDocumentMgr_->Release();
}

void ConsoleWnd::activated()
{
	tsfThreadMgr_->SetFocus(tsfDocumentMgr_);
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

void ConsoleWnd::inputBufferUpdated()
{
	bufferUpdated();
}

void ConsoleWnd::drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly)
{
	if(scrolly != cacheScrolly_ || scrollx != cacheScrollx_ || width != cacheWidth_ || height != cacheHeight_)
		updateCache(width, height, scrollx, scrolly);

	Gdiplus::Graphics g(hdc);
	g.DrawImage(cacheBitmap_.get(), x, y);
}

bool ConsoleWnd::onKeyDown(int vk)
{
	if(vk == VK_DELETE)	
		deleteOrBackspace(false);
	else if(vk == VK_LEFT)
	{
		if(selStart_ != selEnd_)
			selStart_ = selEnd_;
		else if(selStart_ > 0)
		{
			selStart_ --;
			selEnd_ = selStart_;
		}
	}
	else if(vk == VK_RIGHT)
	{
		if(selStart_ != selEnd_)
			selEnd_ = selStart_;
		else if(selStart_ < inputBuffer_.size())
		{
			selStart_ ++;
			selEnd_ = selStart_;
		}
	}
	else if(vk == VK_UP)
		return false;
	else if(vk == VK_DOWN)
		return false;

	return false;
}

bool ConsoleWnd::deleteOrBackspace(bool isBackspace)
{
	if(isBackspace && selStart_ == 0)
		return false;
	if(!isBackspace && selEnd_ == inputBuffer_.size())
		return false;
	if(selStart_ != selEnd_)
	{
		inputBuffer_.erase(selStart_, selStart_ - selEnd_ + 1);
		selEnd_ = selStart_;
	}
	else
	{
		size_t pos = selStart_ - 1;
		if(!isBackspace)
			pos ++;
		inputBuffer_.erase(pos, 1);
		selStart_ = selEnd_ = pos;
	}

	if(host_->getInputMode() & ENABLE_ECHO_INPUT)
		inputBufferUpdated();
	return true;
}

void ConsoleWnd::checkPendingRead()
{
	if(!currentReadSize_)
		return;
	if(!(host_->getInputMode() & ENABLE_LINE_INPUT))
	{
		size_t size = std::min(currentReadSize_, inputBuffer_.size());
		host_->write(inputBuffer_.substr(0, size));
		inputBuffer_.erase(0, size);
	}
	else
	{
		size_t pos;
		if((pos = inputBuffer_.find(L'\n')) != std::wstring::npos)
		{
			pos ++;
			std::wstring buffer = inputBuffer_.substr(0, pos);
			appendStringToBuffer(buffer);
			buffer.replace(buffer.end() - 1, buffer.end(), L"\r\n");
			host_->write(buffer);
			inputBuffer_.erase(0, pos);
			selStart_ = selEnd_ = 0;
		}
	}
}

void ConsoleWnd::handleRead(size_t size)
{
	currentReadSize_ = size;
	checkPendingRead();
}

bool ConsoleWnd::appendCharacter(const std::wstring &buffer)
{
	if(buffer.size() == 0)
		return false;

	if(!(host_->getInputMode() & ENABLE_LINE_INPUT))
		inputBuffer_.append(buffer);
	else
	{
		if(buffer[0] == L'\b' && buffer.size() == 1) //backspace
			return deleteOrBackspace(true);
		else
		{
			if(selStart_ != selEnd_)
			{
				inputBuffer_.erase(selStart_, selStart_ - selEnd_ + 1);
				selEnd_ = selStart_;
			}
			inputBuffer_.insert(selEnd_, buffer);
			selEnd_ += buffer.size();
			selStart_ = selEnd_;
		}
	}

	checkPendingRead();

	if(host_->getInputMode() & ENABLE_ECHO_INPUT)
		inputBufferUpdated();
	return true;
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


//IUnknown
ULONG STDMETHODCALLTYPE ConsoleWnd::AddRef()
{
	return 1;
}

ULONG STDMETHODCALLTYPE ConsoleWnd::Release()
{
	return 1;
}

STDMETHODIMP ConsoleWnd::QueryInterface(REFIID riid, __RPC__deref_out void **ppvObject)
{
	if(riid == IID_IUnknown)
		*ppvObject = static_cast<IUnknown *>(static_cast<ITextStoreACP *>(this));
	else if(riid == IID_ITextStoreACP)
		*ppvObject = static_cast<ITextStoreACP *>(this);
	else if(riid == IID_ITfContextOwnerCompositionSink)
		*ppvObject = static_cast<ITfContextOwnerCompositionSink *>(this);
	else
	{
		*ppvObject = NULL;
		return E_NOINTERFACE;
	}

	return S_OK;
}

STDMETHODIMP ConsoleWnd::AdviseSink(REFIID riid, IUnknown *punk, DWORD dwMask)
{
	if(riid == IID_ITextStoreACPSink)
	{
		if(tsfACPSink_)
			tsfACPSink_->Release();
		punk->QueryInterface(&tsfACPSink_);
		tsfACPSink_->AddRef();
	}
	return S_OK;
}

STDMETHODIMP ConsoleWnd::UnadviseSink(IUnknown *punk)
{
	ITextStoreACPSink *sink;
	punk->QueryInterface(&sink);
	if(sink == tsfACPSink_)
	{
		tsfACPSink_->Release();
		tsfACPSink_ = nullptr;
	}
	return S_OK;
}

STDMETHODIMP ConsoleWnd::RequestLock(DWORD dwLockFlags, HRESULT *phrSession)
{
	if(!tsfACPSink_)
		return E_UNEXPECTED;
	*phrSession = tsfACPSink_->OnLockGranted(dwLockFlags);
	return S_OK;
}

STDMETHODIMP ConsoleWnd::GetStatus(TS_STATUS *pdcs)
{
	pdcs->dwDynamicFlags = 0;
	pdcs->dwStaticFlags = TS_SS_NOHIDDENTEXT;
	return S_OK;
}

STDMETHODIMP ConsoleWnd::QueryInsert(LONG acpTestStart, LONG acpTestEnd, ULONG cch, LONG *pacpResultStart, LONG *pacpResultEnd){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetSelection(ULONG ulIndex, ULONG ulCount, TS_SELECTION_ACP *pSelection, ULONG *pcFetched)
{
	*pcFetched = 0;
	if(ulCount)
	{
		pSelection->acpStart = static_cast<LONG>(selStart_);
		pSelection->acpEnd = static_cast<LONG>(selEnd_);
		pSelection->style.ase = (isSelectionEndsAtLeft_ ? TS_AE_START : TS_AE_END);
		pSelection->style.fInterimChar = (isSelectionInterim_ ? TRUE : FALSE);
		*pcFetched = 1;
	}
	return S_OK;
}

STDMETHODIMP ConsoleWnd::SetSelection(ULONG ulCount, const TS_SELECTION_ACP *pSelection)
{
	if(ulCount && pSelection)
	{
		selStart_ = pSelection->acpStart;
		selEnd_ = pSelection->acpEnd;
		isSelectionEndsAtLeft_ = (pSelection->style.ase & TS_AE_START ? true : false);
		isSelectionInterim_ = (pSelection->style.fInterimChar == TRUE);

		inputBufferUpdated();
	}
	return S_OK;
}

STDMETHODIMP ConsoleWnd::GetText(LONG acpStart, LONG acpEnd, WCHAR *pchPlain, ULONG cchPlainReq, ULONG *pcchPlainOut, TS_RUNINFO *prgRunInfo, 
								 ULONG ulRunInfoReq, ULONG *pulRunInfoOut, LONG *pacpNext)
{
	if(acpEnd == -1)
		acpEnd = static_cast<LONG>(inputBuffer_.size() - 1);
	auto out = stdext::checked_array_iterator<wchar_t *>(pchPlain, cchPlainReq);
	std::copy(inputBuffer_.begin() + acpStart, inputBuffer_.begin() + (acpEnd + 1), out);
	*pcchPlainOut = acpEnd - acpStart + 1;

	if(ulRunInfoReq && pchPlain)
	{
		prgRunInfo->uCount = *pcchPlainOut;
		prgRunInfo->type = TS_RT_PLAIN;
		*pulRunInfoOut = 1;
	}
	else
		*pulRunInfoOut = 0;
	*pacpNext = acpEnd + 1;
	return S_OK;
}

STDMETHODIMP ConsoleWnd::SetText(DWORD dwFlags, LONG acpStart, LONG acpEnd, const WCHAR *pchText, ULONG cch, TS_TEXTCHANGE *pChange)
{
	if(acpStart != acpEnd)
		inputBuffer_.erase(acpStart, acpEnd - acpStart);
	inputBuffer_.insert(acpStart, pchText, cch);

	pChange->acpStart = acpStart;
	pChange->acpOldEnd = acpEnd;
	pChange->acpNewEnd = acpStart + cch;
	inputBufferUpdated();

	return S_OK;
}

STDMETHODIMP ConsoleWnd::GetFormattedText(LONG acpStart, LONG acpEnd, IDataObject **ppDataObject){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetEmbedded(LONG acpPos, REFGUID rguidService, REFIID riid, IUnknown **ppunk){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::QueryInsertEmbedded(const GUID *pguidService, const FORMATETC *pFormatEtc, BOOL *pfInsertable){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::InsertEmbedded(DWORD dwFlags, LONG acpStart, LONG acpEnd, IDataObject *pDataObject, TS_TEXTCHANGE *pChange){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::RequestSupportedAttrs(DWORD dwFlags, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::RequestAttrsAtPosition(LONG acpPos, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::RequestAttrsTransitioningAtPosition(LONG acpPos, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::FindNextAttrTransition(LONG acpStart, LONG acpHalt, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags, LONG *pacpNext, BOOL *pfFound, LONG *plFoundOffset){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::RetrieveRequestedAttrs(ULONG ulCount, TS_ATTRVAL *paAttrVals, ULONG *pcFetched){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetEndACP(LONG *pacp){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetActiveView(TsViewCookie *pvcView)
{
	*pvcView = 0;
	return S_OK;
}

STDMETHODIMP ConsoleWnd::GetACPFromPoint(TsViewCookie vcView, const POINT *pt, DWORD dwFlags, LONG *pacp){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetTextExt(TsViewCookie vcView, LONG acpStart, LONG acpEnd, RECT *prc, BOOL *pfClipped){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetScreenExt(TsViewCookie vcView, RECT *prc){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::GetWnd(TsViewCookie vcView, HWND *phwnd)
{
	*phwnd = mainWnd_.lock()->gethWnd();
	return S_OK;
}

STDMETHODIMP ConsoleWnd::InsertTextAtSelection(DWORD dwFlags, const WCHAR *pchText, ULONG cch, LONG *pacpStart, LONG *pacpEnd, TS_TEXTCHANGE *pChange)
{
	if(!(dwFlags & TF_IAS_QUERYONLY))
	{
		if(selStart_ != selEnd_)
			inputBuffer_.erase(selStart_, selEnd_ - selStart_ + 1);
		inputBuffer_.insert(selStart_, pchText, cch);
	}
	if(!(dwFlags & TF_IAS_NOQUERY))
	{
		*pacpStart = static_cast<LONG>(selStart_);
		*pacpEnd = static_cast<LONG>(selStart_) + cch;
	}

	pChange->acpStart = static_cast<LONG>(selStart_);
	pChange->acpOldEnd = static_cast<LONG>(selEnd_);
	pChange->acpNewEnd = static_cast<LONG>(selEnd_) + cch;

	inputBufferUpdated();
	return S_OK;
}
STDMETHODIMP ConsoleWnd::InsertEmbeddedAtSelection(DWORD dwFlags, IDataObject *pDataObject, LONG *pacpStart, LONG *pacpEnd, TS_TEXTCHANGE *pChange){return E_NOTIMPL;}

STDMETHODIMP ConsoleWnd::OnStartComposition(ITfCompositionView *pComposition, BOOL *pfOk)
{
	pComposition->AddRef();
	*pfOk = TRUE;
	return S_OK;
}

STDMETHODIMP ConsoleWnd::OnUpdateComposition(ITfCompositionView *pComposition, ITfRange *pRangeNew){return E_NOTIMPL;}
STDMETHODIMP ConsoleWnd::OnEndComposition(ITfCompositionView *pComposition)
{
	pComposition->Release();
	return S_OK;
}