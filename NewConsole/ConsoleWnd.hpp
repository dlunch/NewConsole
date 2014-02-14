#pragma once

#include <memory>
#include <string>
#include <list>
#include <mutex>

#include <Windows.h>
#include <gdiplus.h>
#include <msctf.h>

#include "ConsoleEventListener.hpp"

class ConsoleHost;
class NewConsole;
class ConsoleWnd : public ConsoleEventListener, public ITextStoreACP, public ITfContextOwnerCompositionSink, public std::enable_shared_from_this<ConsoleWnd>
{
private:
	static ITfThreadMgr *tsfThreadMgr_;
	static TfClientId tsfClientId_;
private:
	ITfDocumentMgr *tsfDocumentMgr_;
	ITfContext *tsfContext_;
	TfEditCookie tsfEditCookie_;
	ITextStoreACPSink *tsfACPSink_;
private:
	std::shared_ptr<ConsoleHost> host_;

	std::shared_ptr<Gdiplus::Bitmap> cacheBitmap_;
	int cacheScrollx_;
	int cacheScrolly_;
	int cacheWidth_;
	int cacheHeight_;
	size_t selStart_;
	size_t selEnd_;
	bool isSelectionInterim_;
	bool isSelectionEndsAtLeft_;
	size_t currentReadSize_;
	uint32_t endMask_;

	std::wstring inputBuffer_;
	std::list<std::pair<std::wstring, float>> buffer_;
	std::mutex bufferLock_;
	std::weak_ptr<NewConsole> mainWnd_;
private:
	virtual void handleRead(size_t size, uint32_t endMask, size_t nInitialBytes);
	virtual void handleWrite(const std::wstring &buffer);

	bool deleteOrBackspace(bool isBackspace);
	void checkPendingRead();
	void updateCache(int width, int height, int scrollx, int scrolly);
	void invalidateCache();
	void bufferUpdated();
	void inputBufferUpdated();
	void appendStringToBuffer(const std::wstring &buffer);
public:
	ConsoleWnd(const std::wstring &cmdline, std::weak_ptr<NewConsole> mainWnd);
	~ConsoleWnd();

	void drawScreenContents(HDC hdc, int x, int y, int width, int height, int scrollx, int scrolly);
	bool appendCharacter(const std::wstring &buffer);
	bool onKeyDown(int vk);
	void activated();

private:
	//IUnknown methods.
	STDMETHOD(QueryInterface)(REFIID, LPVOID*);
	STDMETHOD_(DWORD, AddRef)();
	STDMETHOD_(DWORD, Release)();

	//ITextStoreACP methods.
	STDMETHODIMP AdviseSink(REFIID riid, IUnknown *punk, DWORD dwMask);
	STDMETHODIMP UnadviseSink(IUnknown *punk);
	STDMETHODIMP RequestLock(DWORD dwLockFlags, HRESULT *phrSession);
	STDMETHODIMP GetStatus(TS_STATUS *pdcs);
	STDMETHODIMP QueryInsert(LONG acpTestStart, LONG acpTestEnd, ULONG cch, LONG *pacpResultStart, LONG *pacpResultEnd);
	STDMETHODIMP GetSelection(ULONG ulIndex, ULONG ulCount, TS_SELECTION_ACP *pSelection, ULONG *pcFetched);
	STDMETHODIMP SetSelection(ULONG ulCount, const TS_SELECTION_ACP *pSelection);
	STDMETHODIMP GetText(LONG acpStart, LONG acpEnd, WCHAR *pchPlain, ULONG cchPlainReq, ULONG *pcchPlainOut, TS_RUNINFO *prgRunInfo, ULONG ulRunInfoReq, ULONG *pulRunInfoOut, LONG *pacpNext);
	STDMETHODIMP SetText(DWORD dwFlags, LONG acpStart, LONG acpEnd, const WCHAR *pchText, ULONG cch, TS_TEXTCHANGE *pChange);
	STDMETHODIMP GetFormattedText(LONG acpStart, LONG acpEnd, IDataObject **ppDataObject);
	STDMETHODIMP GetEmbedded(LONG acpPos, REFGUID rguidService, REFIID riid, IUnknown **ppunk);
	STDMETHODIMP QueryInsertEmbedded(const GUID *pguidService, const FORMATETC *pFormatEtc, BOOL *pfInsertable);
	STDMETHODIMP InsertEmbedded(DWORD dwFlags, LONG acpStart, LONG acpEnd, IDataObject *pDataObject, TS_TEXTCHANGE *pChange);
	STDMETHODIMP RequestSupportedAttrs(DWORD dwFlags, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs);
	STDMETHODIMP RequestAttrsAtPosition(LONG acpPos, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags);
	STDMETHODIMP RequestAttrsTransitioningAtPosition(LONG acpPos, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags);
	STDMETHODIMP FindNextAttrTransition(LONG acpStart, LONG acpHalt, ULONG cFilterAttrs, const TS_ATTRID *paFilterAttrs, DWORD dwFlags, LONG *pacpNext, BOOL *pfFound, LONG *plFoundOffset);
	STDMETHODIMP RetrieveRequestedAttrs(ULONG ulCount, TS_ATTRVAL *paAttrVals, ULONG *pcFetched);
	STDMETHODIMP GetEndACP(LONG *pacp);
	STDMETHODIMP GetActiveView(TsViewCookie *pvcView);
	STDMETHODIMP GetACPFromPoint(TsViewCookie vcView, const POINT *pt, DWORD dwFlags, LONG *pacp);
	STDMETHODIMP GetTextExt(TsViewCookie vcView, LONG acpStart, LONG acpEnd, RECT *prc, BOOL *pfClipped);
	STDMETHODIMP GetScreenExt(TsViewCookie vcView, RECT *prc);
	STDMETHODIMP GetWnd(TsViewCookie vcView, HWND *phwnd);
	STDMETHODIMP InsertTextAtSelection(DWORD dwFlags, const WCHAR *pchText, ULONG cch, LONG *pacpStart, LONG *pacpEnd, TS_TEXTCHANGE *pChange);
	STDMETHODIMP InsertEmbeddedAtSelection(DWORD dwFlags, IDataObject *pDataObject, LONG *pacpStart, LONG *pacpEnd, TS_TEXTCHANGE *pChange);

	//ITfContextOwnerCompositionSink methods.
	STDMETHODIMP OnStartComposition(ITfCompositionView *pComposition, BOOL *pfOk);
	STDMETHODIMP OnUpdateComposition(ITfCompositionView *pComposition, ITfRange *pRangeNew);
	STDMETHODIMP OnEndComposition(ITfCompositionView *pComposition);
};
