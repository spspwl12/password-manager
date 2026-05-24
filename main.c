#define _WIN32_WINNT 0x0600
#define COBJMACROS
#include <windows.h>
#include <commctrl.h>
#include <ole2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include "resource.h"
#include "crypto.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")

#define VAULT_MAGIC 0x50574D47 /* 'PWMG' */
#define MAX_ENTRIES 1000

#ifdef UNICODE
#define CF_TTEXT CF_UNICODETEXT
#else
#define CF_TTEXT CF_TEXT
#endif

typedef struct {
    char title[256];
    char username[256];
    uint8_t enc_password[512];
    size_t enc_len;
} PwEntry;

/* Global State */
HINSTANCE hInst;
uint8_t master_key[32];
int is_unlocked = 0;
PwEntry entries[MAX_ENTRIES];
int entry_count = 0;
TCHAR vault_path[MAX_PATH];
uint8_t global_salt[SALT_SIZE];

HFONT g_hListFont = NULL;
HIMAGELIST g_hImageList = NULL;

/* UI Helpers */
void InitListView(HWND hList) {
    g_hListFont = CreateFont(-18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, TEXT("Segoe UI"));
    SendMessage(hList, WM_SETFONT, (WPARAM)g_hListFont, TRUE);
    
    g_hImageList = ImageList_Create(1, 36, ILC_COLOR32, 1, 0);
    ListView_SetImageList(hList, g_hImageList, LVSIL_SMALL);

    LVCOLUMN lvc = {0};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    
    lvc.iSubItem = 0; lvc.cx = 200; lvc.pszText = TEXT("아이디"); ListView_InsertColumn(hList, 0, &lvc);
    lvc.iSubItem = 1; lvc.cx = 300; lvc.pszText = TEXT("비밀번호"); ListView_InsertColumn(hList, 1, &lvc);
    
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

/* UTF-8 Conversion Helpers */
void TcharToUtf8(const TCHAR *in, char *out, size_t out_max) {
#ifdef UNICODE
    WideCharToMultiByte(CP_UTF8, 0, in, -1, out, (int)out_max, NULL, NULL);
#else
    int wlen = MultiByteToWideChar(CP_ACP, 0, in, -1, NULL, 0);
    wchar_t *wstr = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, in, -1, wstr, wlen);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, out, (int)out_max, NULL, NULL);
    free(wstr);
#endif
}

void Utf8ToTchar(const char *in, TCHAR *out, size_t out_max) {
#ifdef UNICODE
    MultiByteToWideChar(CP_UTF8, 0, in, -1, out, (int)out_max);
#else
    int wlen = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    wchar_t *wstr = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, in, -1, wstr, wlen);
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, out, (int)out_max, NULL, NULL);
    free(wstr);
#endif
}

/* Secure Edit Control Subclass */
#define WM_GET_SECURE_TEXT (WM_USER + 100)
#define WM_SET_SECURE_TEXT (WM_USER + 101)

uint8_t ui_session_key[32];

typedef struct {
    uint8_t enc_buffer[512];
    size_t enc_len;
    int len;
    uint8_t iv[16];
} SecureEditData;

static void SecureBufferReplace(SecureEditData *data, int start, int end, const TCHAR *insert_str, int insert_len) {
    TCHAR temp[512] = {0};
    if (data->enc_len > 0) {
        size_t p_len;
        uint8_t *plain = aes_cbc_decrypt(data->enc_buffer, data->enc_len, ui_session_key, data->iv, &p_len);
        if (plain) {
            memcpy(temp, plain, p_len);
            secure_wipe(plain, p_len);
            free(plain);
        }
    }
    
    if (start > end) { int t = start; start = end; end = t; }
    if (start < 0) start = 0;
    if (end > data->len) end = data->len;
    
    int del_len = end - start;
    int tail_len = data->len - end;
    
    if (insert_len != del_len && tail_len > 0) {
        memmove(&temp[start + insert_len], &temp[end], tail_len * sizeof(TCHAR));
    }
    if (insert_len > 0 && insert_str) {
        memcpy(&temp[start], insert_str, insert_len * sizeof(TCHAR));
    }
    
    data->len = data->len - del_len + insert_len;
    temp[data->len] = 0;
    
    if (data->len > 0) {
        secure_rand(data->iv, 16);
        size_t c_len;
        uint8_t *cipher = aes_cbc_encrypt((uint8_t*)temp, (data->len + 1) * sizeof(TCHAR), ui_session_key, data->iv, &c_len);
        if (cipher) {
            memcpy(data->enc_buffer, cipher, c_len);
            data->enc_len = c_len;
            free(cipher);
        }
    } else {
        data->enc_len = 0;
    }
    secure_wipe(temp, sizeof(temp));
}

LRESULT CALLBACK SecureEditProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    SecureEditData *data = (SecureEditData*)dwRefData;
    switch (uMsg) {
        case WM_GET_SECURE_TEXT: {
            TCHAR *out = (TCHAR*)lParam;
            size_t max_len = wParam;
            if (data->len > 0 && data->enc_len > 0) {
                size_t p_len;
                uint8_t *plain = aes_cbc_decrypt(data->enc_buffer, data->enc_len, ui_session_key, data->iv, &p_len);
                if (plain) {
                    _tcscpy_s(out, max_len, (TCHAR*)plain);
                    secure_wipe(plain, p_len);
                    free(plain);
                } else out[0] = 0;
            } else out[0] = 0;
            return TRUE;
        }
        case WM_SET_SECURE_TEXT: {
            const TCHAR *text = (const TCHAR *)lParam;
            SecureBufferReplace(data, 0, data->len, text, (int)_tcslen(text));
            
            TCHAR asterisks[256];
            for (int i=0; i<data->len; i++) asterisks[i] = TEXT('*');
            asterisks[data->len] = 0;
            DefSubclassProc(hwnd, WM_SETTEXT, 0, (LPARAM)asterisks);
            SendMessage(hwnd, EM_SETSEL, data->len, data->len);
            return TRUE;
        }
        case WM_CHAR: {
            TCHAR ch = (TCHAR)wParam;
            DWORD sel = (DWORD)SendMessage(hwnd, EM_GETSEL, 0, 0);
            int start = LOWORD(sel);
            int end = HIWORD(sel);
            
            if (ch == VK_BACK) {
                if (start == end && start > 0) {
                    SecureBufferReplace(data, start - 1, start, NULL, 0);
                } else if (start != end) {
                    SecureBufferReplace(data, start, end, NULL, 0);
                }
                return DefSubclassProc(hwnd, uMsg, wParam, lParam);
            } else if (ch >= 32) {
                if (data->len < 255) {
                    SecureBufferReplace(data, start, end, &ch, 1);
                    return DefSubclassProc(hwnd, uMsg, (WPARAM)TEXT('*'), lParam);
                }
                return 0;
            }
            break;
        }
        case WM_KEYDOWN: {
            if (wParam == VK_DELETE) {
                DWORD sel = (DWORD)SendMessage(hwnd, EM_GETSEL, 0, 0);
                int start = LOWORD(sel);
                int end = HIWORD(sel);
                if (start == end && start < data->len) {
                    SecureBufferReplace(data, start, start + 1, NULL, 0);
                } else if (start != end) {
                    SecureBufferReplace(data, start, end, NULL, 0);
                }
                return DefSubclassProc(hwnd, uMsg, wParam, lParam);
            }
            break;
        }
        case WM_PASTE: {
            if (OpenClipboard(hwnd)) {
#ifdef UNICODE
                HANDLE hData = GetClipboardData(CF_UNICODETEXT);
#else
                HANDLE hData = GetClipboardData(CF_TEXT);
#endif
                if (hData) {
                    TCHAR *clip_text = GlobalLock(hData);
                    if (clip_text) {
                        int clip_len = (int)_tcslen(clip_text);
                        DWORD sel = (DWORD)SendMessage(hwnd, EM_GETSEL, 0, 0);
                        int start = LOWORD(sel);
                        int end = HIWORD(sel);
                        if (start > end) { int t = start; start = end; end = t; }
                        
                        if (data->len - (end - start) + clip_len <= 255) {
                            SecureBufferReplace(data, start, end, clip_text, clip_len);
                            
                            TCHAR asterisks[256];
                            for(int i=0; i<clip_len && i<255; i++) asterisks[i] = TEXT('*');
                            asterisks[clip_len < 256 ? clip_len : 255] = 0;
                            SendMessage(hwnd, EM_REPLACESEL, TRUE, (LPARAM)asterisks);
                        }
                        GlobalUnlock(hData);
                    }
                }
                CloseClipboard();
            }
            return 0;
        }
        case WM_COPY:
        case WM_CUT: {
            DWORD sel = (DWORD)SendMessage(hwnd, EM_GETSEL, 0, 0);
            int start = LOWORD(sel);
            int end = HIWORD(sel);
            if (start > end) { int t = start; start = end; end = t; }
            if (start != end) {
                TCHAR temp[512] = {0};
                if (data->enc_len > 0) {
                    size_t p_len;
                    uint8_t *plain = aes_cbc_decrypt(data->enc_buffer, data->enc_len, ui_session_key, data->iv, &p_len);
                    if (plain) {
                        memcpy(temp, plain, p_len);
                        secure_wipe(plain, p_len);
                        free(plain);
                    }
                }
                int copy_len = end - start;
                TCHAR *copy_str = malloc((copy_len + 1) * sizeof(TCHAR));
                memcpy(copy_str, &temp[start], copy_len * sizeof(TCHAR));
                copy_str[copy_len] = 0;
                
                if (OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    size_t bytes = (copy_len + 1) * sizeof(TCHAR);
                    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
                    memcpy(GlobalLock(hg), copy_str, bytes);
                    GlobalUnlock(hg);
#ifdef UNICODE
                    SetClipboardData(CF_UNICODETEXT, hg);
#else
                    SetClipboardData(CF_TEXT, hg);
#endif
                    CloseClipboard();
                }
                secure_wipe(copy_str, copy_len * sizeof(TCHAR));
                free(copy_str);
                
                if (uMsg == WM_CUT) {
                    SecureBufferReplace(data, start, end, NULL, 0);
                    SendMessage(hwnd, EM_REPLACESEL, TRUE, (LPARAM)TEXT(""));
                }
                secure_wipe(temp, sizeof(temp));
            }
            return 0;
        }
        case WM_IME_STARTCOMPOSITION:
        case WM_IME_COMPOSITION:
        case WM_IME_ENDCOMPOSITION:
        case WM_IME_CHAR:
        case WM_CONTEXTMENU:
            return 0;
        case WM_NCDESTROY:
            secure_wipe(data->enc_buffer, sizeof(data->enc_buffer));
            RemoveWindowSubclass(hwnd, SecureEditProc, uIdSubclass);
            free(data);
            break;
    }
    return DefSubclassProc(hwnd, uMsg, wParam, lParam);
}

void AttachSecureEdit(HWND hEdit) {
    SecureEditData *data = calloc(1, sizeof(SecureEditData));
    SetWindowSubclass(hEdit, SecureEditProc, 1, (DWORD_PTR)data);
    LONG_PTR style = GetWindowLongPtr(hEdit, GWL_STYLE);
    SetWindowLongPtr(hEdit, GWL_STYLE, style & ~ES_PASSWORD);
}

void GetSecureEditText(HWND hEdit, TCHAR *out, size_t max_len) {
    if (!SendMessage(hEdit, WM_GET_SECURE_TEXT, max_len, (LPARAM)out)) {
        out[0] = 0;
    }
}

void SetSecureEditText(HWND hEdit, const TCHAR *text) {
    SendMessage(hEdit, WM_SET_SECURE_TEXT, 0, (LPARAM)text);
}

void RefreshList(HWND hList) {
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < entry_count; i++) {
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        
        TCHAR t_user[256];
        Utf8ToTchar(entries[i].username, t_user, 256);
        lvi.iSubItem = 0; lvi.pszText = t_user;
        ListView_InsertItem(hList, &lvi);
        
        lvi.iSubItem = 1; lvi.pszText = TEXT("********");
        ListView_SetItemText(hList, i, 1, lvi.pszText);
    }
}

/* OLE Drag & Drop Implementation in plain C */
typedef struct {
    IEnumFORMATETCVtbl *lpVtbl;
    LONG ref_count;
    ULONG current;
} CEnumFormatEtc;

HRESULT STDMETHODCALLTYPE EnumFmt_QueryInterface(IEnumFORMATETC *This, REFIID riid, void **ppv) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IEnumFORMATETC)) {
        *ppv = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    *ppv = NULL; return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE EnumFmt_AddRef(IEnumFORMATETC *This) {
    CEnumFormatEtc *p = (CEnumFormatEtc*)This;
    return InterlockedIncrement(&p->ref_count);
}
ULONG STDMETHODCALLTYPE EnumFmt_Release(IEnumFORMATETC *This) {
    CEnumFormatEtc *p = (CEnumFormatEtc*)This;
    ULONG ref = InterlockedDecrement(&p->ref_count);
    if (ref == 0) free(p);
    return ref;
}
HRESULT STDMETHODCALLTYPE EnumFmt_Next(IEnumFORMATETC *This, ULONG celt, FORMATETC *rgelt, ULONG *pceltFetched) {
    CEnumFormatEtc *p = (CEnumFormatEtc*)This;
    if (p->current == 0 && celt > 0) {
        rgelt[0].cfFormat = CF_UNICODETEXT;
        rgelt[0].ptd = NULL;
        rgelt[0].dwAspect = DVASPECT_CONTENT;
        rgelt[0].lindex = -1;
        rgelt[0].tymed = TYMED_HGLOBAL;
        p->current = 1;
        if (pceltFetched) *pceltFetched = 1;
        return celt == 1 ? S_OK : S_FALSE;
    }
    if (pceltFetched) *pceltFetched = 0;
    return S_FALSE;
}
HRESULT STDMETHODCALLTYPE EnumFmt_Skip(IEnumFORMATETC *This, ULONG celt) {
    CEnumFormatEtc *p = (CEnumFormatEtc*)This;
    p->current += celt;
    return (p->current <= 1) ? S_OK : S_FALSE;
}
HRESULT STDMETHODCALLTYPE EnumFmt_Reset(IEnumFORMATETC *This) {
    ((CEnumFormatEtc*)This)->current = 0;
    return S_OK;
}
HRESULT STDMETHODCALLTYPE EnumFmt_Clone(IEnumFORMATETC *This, IEnumFORMATETC **ppEnum) { return E_NOTIMPL; }

IEnumFORMATETCVtbl EnumFmtVtbl = {
    EnumFmt_QueryInterface, EnumFmt_AddRef, EnumFmt_Release,
    EnumFmt_Next, EnumFmt_Skip, EnumFmt_Reset, EnumFmt_Clone
};

typedef struct {
    IDataObjectVtbl *lpVtbl;
    LONG ref_count;
    WCHAR *text;
} CDataObject;

HRESULT STDMETHODCALLTYPE DataObject_QueryInterface(IDataObject *This, REFIID riid, void **ppvObject) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDataObject)) {
        *ppvObject = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    *ppvObject = NULL;
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE DataObject_AddRef(IDataObject *This) {
    CDataObject *pThis = (CDataObject *)This;
    return InterlockedIncrement(&pThis->ref_count);
}
ULONG STDMETHODCALLTYPE DataObject_Release(IDataObject *This) {
    CDataObject *pThis = (CDataObject *)This;
    ULONG ref = InterlockedDecrement(&pThis->ref_count);
    if (ref == 0) {
        if (pThis->text) {
            secure_wipe(pThis->text, wcslen(pThis->text) * sizeof(WCHAR));
            free(pThis->text);
        }
        free(pThis);
    }
    return ref;
}
HRESULT STDMETHODCALLTYPE DataObject_GetData(IDataObject *This, FORMATETC *pformatetcIn, STGMEDIUM *pmedium) {
    CDataObject *pThis = (CDataObject *)This;
    if (pformatetcIn->cfFormat == CF_UNICODETEXT && (pformatetcIn->tymed & TYMED_HGLOBAL)) {
        size_t bytes = (wcslen(pThis->text) + 1) * sizeof(WCHAR);
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
        memcpy(GlobalLock(hg), pThis->text, bytes);
        GlobalUnlock(hg);
        
        pmedium->tymed = TYMED_HGLOBAL;
        pmedium->hGlobal = hg;
        pmedium->pUnkForRelease = NULL;
        return S_OK;
    }
    return DV_E_FORMATETC;
}
HRESULT STDMETHODCALLTYPE DataObject_GetDataHere(IDataObject *This, FORMATETC *pformatetc, STGMEDIUM *pmedium) { return E_NOTIMPL; }
HRESULT STDMETHODCALLTYPE DataObject_QueryGetData(IDataObject *This, FORMATETC *pformatetc) {
    if (pformatetc->cfFormat == CF_UNICODETEXT && (pformatetc->tymed & TYMED_HGLOBAL)) return S_OK;
    return DV_E_FORMATETC;
}
HRESULT STDMETHODCALLTYPE DataObject_GetCanonicalFormatEtc(IDataObject *This, FORMATETC *pformatectIn, FORMATETC *pformatetcOut) { return E_NOTIMPL; }
HRESULT STDMETHODCALLTYPE DataObject_SetData(IDataObject *This, FORMATETC *pformatetc, STGMEDIUM *pmedium, BOOL fRelease) { return E_NOTIMPL; }
HRESULT STDMETHODCALLTYPE DataObject_EnumFormatEtc(IDataObject *This, DWORD dwDirection, IEnumFORMATETC **ppenumFormatEtc) {
    if (dwDirection == DATADIR_GET) {
        CEnumFormatEtc *e = (CEnumFormatEtc*)malloc(sizeof(CEnumFormatEtc));
        e->lpVtbl = &EnumFmtVtbl;
        e->ref_count = 1;
        e->current = 0;
        *ppenumFormatEtc = (IEnumFORMATETC*)e;
        return S_OK;
    }
    return E_NOTIMPL;
}
HRESULT STDMETHODCALLTYPE DataObject_DAdvise(IDataObject *This, FORMATETC *pformatetc, DWORD advf, IAdviseSink *pAdvSink, DWORD *pdwConnection) { return OLE_E_ADVISENOTSUPPORTED; }
HRESULT STDMETHODCALLTYPE DataObject_DUnadvise(IDataObject *This, DWORD dwConnection) { return OLE_E_ADVISENOTSUPPORTED; }
HRESULT STDMETHODCALLTYPE DataObject_EnumDAdvise(IDataObject *This, IEnumSTATDATA **ppenumAdvise) { return OLE_E_ADVISENOTSUPPORTED; }

IDataObjectVtbl DataObjectVtbl = {
    DataObject_QueryInterface, DataObject_AddRef, DataObject_Release,
    DataObject_GetData, DataObject_GetDataHere, DataObject_QueryGetData,
    DataObject_GetCanonicalFormatEtc, DataObject_SetData, DataObject_EnumFormatEtc,
    DataObject_DAdvise, DataObject_DUnadvise, DataObject_EnumDAdvise
};

IDataObject* CreateDataObject(const TCHAR *text) {
    CDataObject *obj = (CDataObject*)malloc(sizeof(CDataObject));
    obj->lpVtbl = &DataObjectVtbl;
    obj->ref_count = 1;
#ifdef UNICODE
    obj->text = _wcsdup(text);
#else
    int wlen = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
    obj->text = malloc(wlen * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, text, -1, obj->text, wlen);
#endif
    return (IDataObject*)obj;
}

typedef struct {
    IDropSourceVtbl *lpVtbl;
    LONG ref_count;
} CDropSource;

HRESULT STDMETHODCALLTYPE DropSource_QueryInterface(IDropSource *This, REFIID riid, void **ppvObject) {
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IDropSource)) {
        *ppvObject = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    *ppvObject = NULL;
    return E_NOINTERFACE;
}
ULONG STDMETHODCALLTYPE DropSource_AddRef(IDropSource *This) {
    CDropSource *pThis = (CDropSource *)This;
    return InterlockedIncrement(&pThis->ref_count);
}
ULONG STDMETHODCALLTYPE DropSource_Release(IDropSource *This) {
    CDropSource *pThis = (CDropSource *)This;
    ULONG ref = InterlockedDecrement(&pThis->ref_count);
    if (ref == 0) free(pThis);
    return ref;
}
HRESULT STDMETHODCALLTYPE DropSource_QueryContinueDrag(IDropSource *This, BOOL fEscapePressed, DWORD grfKeyState) {
    if (fEscapePressed) return DRAGDROP_S_CANCEL;
    if (!(grfKeyState & MK_LBUTTON)) return DRAGDROP_S_DROP;
    return S_OK;
}
HRESULT STDMETHODCALLTYPE DropSource_GiveFeedback(IDropSource *This, DWORD dwEffect) {
    return DRAGDROP_S_USEDEFAULTCURSORS;
}

IDropSourceVtbl DropSourceVtbl = {
    DropSource_QueryInterface, DropSource_AddRef, DropSource_Release,
    DropSource_QueryContinueDrag, DropSource_GiveFeedback
};

IDropSource* CreateDropSource() {
    CDropSource *obj = (CDropSource*)malloc(sizeof(CDropSource));
    obj->lpVtbl = &DropSourceVtbl;
    obj->ref_count = 1;
    return (IDropSource*)obj;
}

void DoDragDropText(const TCHAR *text) {
    IDataObject *pDataObject = CreateDataObject(text);
    IDropSource *pDropSource = CreateDropSource();
    DWORD dwEffect;
    DoDragDrop(pDataObject, pDropSource, DROPEFFECT_COPY, &dwEffect);
    pDataObject->lpVtbl->Release(pDataObject);
    pDropSource->lpVtbl->Release(pDropSource);
}


/* File I/O */
void DeriveMasterKey(const TCHAR *pw, uint8_t *salt, uint8_t *out_key) {
#ifdef UNICODE
    int len = WideCharToMultiByte(CP_UTF8, 0, pw, -1, NULL, 0, NULL, NULL);
    uint8_t *utf8_pw = malloc(len);
    WideCharToMultiByte(CP_UTF8, 0, pw, -1, (char*)utf8_pw, len, NULL, NULL);
    pbkdf2(utf8_pw, len - 1, salt, SALT_SIZE, PBKDF2_ITER, out_key, 32);
    secure_wipe(utf8_pw, len);
    free(utf8_pw);
#else
    int wlen = MultiByteToWideChar(CP_ACP, 0, pw, -1, NULL, 0);
    wchar_t *wstr = malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, pw, -1, wstr, wlen);
    
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    uint8_t *utf8_pw = malloc(len);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char*)utf8_pw, len, NULL, NULL);
    
    pbkdf2(utf8_pw, len - 1, salt, SALT_SIZE, PBKDF2_ITER, out_key, 32);
    
    secure_wipe(wstr, wlen * sizeof(wchar_t));
    free(wstr);
    secure_wipe(utf8_pw, len);
    free(utf8_pw);
#endif
}

void SaveVault() {
    if (!is_unlocked) return;
    FILE *f = _tfopen(vault_path, TEXT("wb"));
    if (!f) return;
    
    uint32_t magic = VAULT_MAGIC;
    fwrite(&magic, 4, 1, f);
    
    fwrite(global_salt, SALT_SIZE, 1, f);
    
    uint8_t iv[16];
    secure_rand(iv, 16);
    fwrite(iv, 16, 1, f);
    
    size_t pdata_len = sizeof(int) + sizeof(PwEntry) * entry_count;
    uint8_t *pdata = malloc(pdata_len);
    memcpy(pdata, &entry_count, sizeof(int));
    memcpy(pdata + sizeof(int), entries, sizeof(PwEntry) * entry_count);
    
    size_t outLen = 0;
    uint8_t *cipher = aes_cbc_encrypt(pdata, pdata_len, master_key, iv, &outLen);
    free(pdata);
    
    if (cipher) {
        fwrite(&outLen, sizeof(size_t), 1, f);
        fwrite(cipher, 1, outLen, f);
        
        uint8_t mac[32];
        hmac_sha256(master_key, 32, cipher, outLen, mac);
        fwrite(mac, 32, 1, f);
        
        free(cipher);
    }
    fclose(f);
}

int LoadVault(const TCHAR *master_pw) {
    FILE *f = _tfopen(vault_path, TEXT("rb"));
    if (!f) return -1;
    
    uint32_t magic;
    if (fread(&magic, 4, 1, f) != 1 || magic != VAULT_MAGIC) { fclose(f); return 0; }
    
    if (fread(global_salt, SALT_SIZE, 1, f) != 1) { fclose(f); return 0; }
    
    uint8_t iv[16];
    if (fread(iv, 16, 1, f) != 1) { fclose(f); return 0; }
    
    uint8_t test_key[32];
    DeriveMasterKey(master_pw, global_salt, test_key);
    
    size_t c_len;
    if (fread(&c_len, sizeof(size_t), 1, f) != 1) { fclose(f); return 0; }
    
    uint8_t *cipher = malloc(c_len);
    fread(cipher, 1, c_len, f);
    
    uint8_t mac[32];
    fread(mac, 32, 1, f);
    fclose(f);
    
    uint8_t calc_mac[32];
    hmac_sha256(test_key, 32, cipher, c_len, calc_mac);
    if (memcmp(mac, calc_mac, 32) != 0) {
        free(cipher);
        return 0; /* Bad password */
    }
    
    size_t outLen = 0;
    uint8_t *plain = aes_cbc_decrypt(cipher, c_len, test_key, iv, &outLen);
    free(cipher);
    
    if (!plain) return 0;
    
    memcpy(&entry_count, plain, sizeof(int));
    memcpy(entries, plain + sizeof(int), sizeof(PwEntry) * entry_count);
    free(plain);
    
    memcpy(master_key, test_key, 32);
    secure_wipe(test_key, 32);
    is_unlocked = 1;
    return 1;
}

/* Clipboard / AutoType */
void CopyToClipboard(HWND hwnd, const TCHAR *text) {
    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        size_t byte_len = (_tcslen(text) + 1) * sizeof(TCHAR);
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if (hg) {
            memcpy(GlobalLock(hg), text, byte_len);
            GlobalUnlock(hg);
            SetClipboardData(CF_TTEXT, hg);
        }
        CloseClipboard();
        SetTimer(hwnd, TIMER_CLIPCLEAR, 10000, NULL); /* 10s */
    }
}

/* Dialog Procs */
INT_PTR CALLBACK EntryDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int edit_idx = -1;
    switch (msg) {
        case WM_INITDIALOG: {
            edit_idx = (int)lParam;
            AttachSecureEdit(GetDlgItem(hwnd, IDC_EDIT_PASSWORD));
            
            if (edit_idx >= 0) {
                TCHAR t_user[256];
                Utf8ToTchar(entries[edit_idx].username, t_user, 256);
                
                SetDlgItemText(hwnd, IDC_EDIT_USERNAME, t_user);
                
                uint8_t iv[16] = {0};
                size_t len = 0;
                uint8_t *pw_bytes = aes_cbc_decrypt(entries[edit_idx].enc_password, entries[edit_idx].enc_len, master_key, iv, &len);
                if (pw_bytes) {
                    char *utf8_pw = (char*)pw_bytes;
                    utf8_pw[len] = 0;
                    
                    TCHAR t_pw[256];
                    Utf8ToTchar(utf8_pw, t_pw, 256);
                    
                    SetSecureEditText(GetDlgItem(hwnd, IDC_EDIT_PASSWORD), t_pw);
                    secure_wipe(t_pw, sizeof(t_pw));
                    secure_wipe(pw_bytes, len);
                    free(pw_bytes);
                }
            }
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                TCHAR user[256], pass[256];
                GetDlgItemText(hwnd, IDC_EDIT_USERNAME, user, 256);
                GetSecureEditText(GetDlgItem(hwnd, IDC_EDIT_PASSWORD), pass, 256);
                
                int idx = edit_idx >= 0 ? edit_idx : entry_count;
                entries[idx].title[0] = '\0';
                TcharToUtf8(user, entries[idx].username, 256);
                
                char utf8_pass[512];
                TcharToUtf8(pass, utf8_pass, 512);
                
                uint8_t iv[16] = {0};
                size_t c_len = 0;
                size_t pass_byte_len = strlen(utf8_pass);
                uint8_t *c = aes_cbc_encrypt((uint8_t*)utf8_pass, pass_byte_len, master_key, iv, &c_len);
                if (c) {
                    memcpy(entries[idx].enc_password, c, c_len);
                    entries[idx].enc_len = c_len;
                    free(c);
                }
                secure_wipe(pass, sizeof(pass));
                secure_wipe(utf8_pass, sizeof(utf8_pass));
                
                if (edit_idx < 0) entry_count++;
                EndDialog(hwnd, 1);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwnd, 0);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

INT_PTR CALLBACK MasterDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            AttachSecureEdit(GetDlgItem(hwnd, IDC_EDIT_MASTER));
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                TCHAR pw[128];
                GetSecureEditText(GetDlgItem(hwnd, IDC_EDIT_MASTER), pw, 128);
                if (LoadVault(pw) == 1) {
                    secure_wipe(pw, sizeof(pw));
                    EndDialog(hwnd, 1);
                } else {
                    MessageBox(hwnd, TEXT("비밀번호가 틀렸거나 파일을 읽을 수 없습니다."), TEXT("오류"), MB_ICONERROR);
                }
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwnd, 0);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

INT_PTR CALLBACK NewVaultDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            AttachSecureEdit(GetDlgItem(hwnd, IDC_EDIT_NEWPW1));
            AttachSecureEdit(GetDlgItem(hwnd, IDC_EDIT_NEWPW2));
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                TCHAR pw1[128], pw2[128];
                GetSecureEditText(GetDlgItem(hwnd, IDC_EDIT_NEWPW1), pw1, 128);
                GetSecureEditText(GetDlgItem(hwnd, IDC_EDIT_NEWPW2), pw2, 128);
                if (_tcscmp(pw1, pw2) != 0) {
                    MessageBox(hwnd, TEXT("비밀번호가 일치하지 않습니다."), TEXT("오류"), MB_ICONERROR);
                    return TRUE;
                }
                if (_tcslen(pw1) < 4) {
                    MessageBox(hwnd, TEXT("비밀번호가 너무 짧습니다."), TEXT("오류"), MB_ICONERROR);
                    return TRUE;
                }
                
                secure_rand(global_salt, SALT_SIZE);
                DeriveMasterKey(pw1, global_salt, master_key);
                secure_wipe(pw1, sizeof(pw1));
                secure_wipe(pw2, sizeof(pw2));
                
                is_unlocked = 1;
                SaveVault();
                
                EndDialog(hwnd, 1);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwnd, 0);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

INT_PTR CALLBACK MainDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static int prev_cx = 0, prev_cy = 0;
    switch (msg) {
        case WM_INITDIALOG: {
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
            prev_cx = rcClient.right;
            prev_cy = rcClient.bottom;
            
            GetModuleFileName(NULL, vault_path, MAX_PATH);
            TCHAR *p = _tcsrchr(vault_path, _T('\\'));
            if (p) _tcscpy_s(p + 1, MAX_PATH - (p - vault_path) - 1, TEXT("vault.dat"));
            
            InitListView(GetDlgItem(hwnd, IDC_LISTVIEW));
            
            FILE *f = _tfopen(vault_path, TEXT("rb"));
            if (f) {
                fclose(f);
                if (DialogBox(hInst, MAKEINTRESOURCE(IDD_MASTER), hwnd, MasterDlgProc) != 1) {
                    PostQuitMessage(0);
                    return TRUE;
                }
            } else {
                if (DialogBox(hInst, MAKEINTRESOURCE(IDD_NEWVAULT), hwnd, NewVaultDlgProc) != 1) {
                    PostQuitMessage(0);
                    return TRUE;
                }
            }
            RefreshList(GetDlgItem(hwnd, IDC_LISTVIEW));
            return TRUE;
        }
        case WM_SIZE: {
            if (wParam == SIZE_MINIMIZED) return TRUE;
            int cx = LOWORD(lParam);
            int cy = HIWORD(lParam);
            if (prev_cx == 0 || prev_cy == 0) return TRUE;
            
            int dx = cx - prev_cx;
            int dy = cy - prev_cy;
            
            HDWP hdwp = BeginDeferWindowPos(12);
            
            #define MOVE_CTRL(id, mx, my, rw, rh) \
                do { \
                    HWND hc = GetDlgItem(hwnd, (id)); \
                    if (hc) { \
                        RECT rc; GetWindowRect(hc, &rc); \
                        MapWindowPoints(HWND_DESKTOP, hwnd, (LPPOINT)&rc, 2); \
                        hdwp = DeferWindowPos(hdwp, hc, NULL, \
                            rc.left + ((mx) ? dx : 0), rc.top + ((my) ? dy : 0), \
                            (rc.right - rc.left) + ((rw) ? dx : 0), (rc.bottom - rc.top) + ((rh) ? dy : 0), \
                            SWP_NOZORDER); \
                    } \
                } while(0)
            
            MOVE_CTRL(IDC_LISTVIEW, 0, 0, 1, 1);
            
            MOVE_CTRL(IDC_BTN_ADD, 0, 1, 0, 0);
            MOVE_CTRL(IDC_BTN_EDIT, 0, 1, 0, 0);
            MOVE_CTRL(IDC_BTN_DELETE, 0, 1, 0, 0);
            MOVE_CTRL(IDC_CHK_ALWAYSONTOP, 0, 1, 0, 0);
            MOVE_CTRL(IDC_STATIC_STATUS, 0, 1, 1, 0);

            MOVE_CTRL(IDC_GROUP_PASTE, 0, 1, 1, 0);
            MOVE_CTRL(IDC_BTN_COPYID, 1, 1, 0, 0);
            MOVE_CTRL(IDC_BTN_COPYPW, 1, 1, 0, 0);
            
            EndDeferWindowPos(hdwp);
            
            prev_cx = cx;
            prev_cy = cy;
            
            InvalidateRect(hwnd, NULL, TRUE);
            return TRUE;
        }
        case WM_NOTIFY: {
            LPNMHDR lpnm = (LPNMHDR)lParam;
            if (lpnm->idFrom == IDC_LISTVIEW && lpnm->code == LVN_BEGINDRAG) {
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                int sel = pnmv->iItem;
                if (sel >= 0) {
                    LVHITTESTINFO hti;
                    hti.pt = pnmv->ptAction;
                    ListView_SubItemHitTest(lpnm->hwndFrom, &hti);
                    
                    if (hti.iSubItem == 0) { /* Username Dragged */
                        TCHAR t_user[256];
                        Utf8ToTchar(entries[sel].username, t_user, 256);
                        DoDragDropText(t_user);
                    } else if (hti.iSubItem == 1) { /* Password Dragged */
                        uint8_t iv[16] = {0};
                        size_t len = 0;
                        uint8_t *pw_bytes = aes_cbc_decrypt(entries[sel].enc_password, entries[sel].enc_len, master_key, iv, &len);
                        if (pw_bytes) {
                            char *utf8_pw = (char*)pw_bytes;
                            utf8_pw[len] = 0;
                            TCHAR t_pw[256];
                            Utf8ToTchar(utf8_pw, t_pw, 256);
                            
                            DoDragDropText(t_pw);
                            
                            secure_wipe(t_pw, sizeof(t_pw));
                            secure_wipe(pw_bytes, len);
                            free(pw_bytes);
                        }
                    }
                }
            }
            return TRUE;
        }
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            HWND hList = GetDlgItem(hwnd, IDC_LISTVIEW);
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            
            if (id == IDC_BTN_ADD) {
                if (DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_ENTRY), hwnd, EntryDlgProc, -1)) {
                    SaveVault();
                    RefreshList(hList);
                }
            } else if (id == IDC_BTN_EDIT && sel >= 0) {
                if (DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_ENTRY), hwnd, EntryDlgProc, sel)) {
                    SaveVault();
                    RefreshList(hList);
                }
            } else if (id == IDC_BTN_DELETE && sel >= 0) {
                if (MessageBox(hwnd, TEXT("정말 삭제하시겠습니까?"), TEXT("확인"), MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    for (int i = sel; i < entry_count - 1; i++) {
                        entries[i] = entries[i+1];
                    }
                    entry_count--;
                    SaveVault();
                    RefreshList(hList);
                }
            } else if (id == IDC_BTN_COPYID && sel >= 0) {
                TCHAR t_user[256];
                Utf8ToTchar(entries[sel].username, t_user, 256);
                CopyToClipboard(hwnd, t_user);
                SetDlgItemText(hwnd, IDC_STATIC_STATUS, TEXT("아이디가 복사되었습니다 (10초 후 삭제)."));
            } else if (id == IDC_BTN_COPYPW && sel >= 0) {
                uint8_t iv[16] = {0};
                size_t len = 0;
                uint8_t *pw_bytes = aes_cbc_decrypt(entries[sel].enc_password, entries[sel].enc_len, master_key, iv, &len);
                if (pw_bytes) {
                    char *utf8_pw = (char*)pw_bytes;
                    utf8_pw[len] = 0;
                    
                    TCHAR t_pw[256];
                    Utf8ToTchar(utf8_pw, t_pw, 256);
                    
                    CopyToClipboard(hwnd, t_pw);
                    secure_wipe(t_pw, sizeof(t_pw));
                    secure_wipe(pw_bytes, len);
                    free(pw_bytes);
                    SetDlgItemText(hwnd, IDC_STATIC_STATUS, TEXT("비밀번호가 복사되었습니다 (10초 후 삭제)."));
                }
            } else if (id == IDC_CHK_ALWAYSONTOP) {
                BOOL isTop = IsDlgButtonChecked(hwnd, IDC_CHK_ALWAYSONTOP);
                SetWindowPos(hwnd, isTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            }
            return TRUE;
        }
        case WM_TIMER:
            if (wParam == TIMER_CLIPCLEAR) {
                KillTimer(hwnd, TIMER_CLIPCLEAR);
                if (OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    CloseClipboard();
                }
                SetDlgItemText(hwnd, IDC_STATIC_STATUS, TEXT("클립보드가 지워졌습니다."));
            }
            return TRUE;
        case WM_CLOSE:
            secure_wipe(master_key, 32);
            DestroyWindow(hwnd);
            return TRUE;
        case WM_DESTROY:
            if (g_hListFont) DeleteObject(g_hListFont);
            if (g_hImageList) ImageList_Destroy(g_hImageList);
            PostQuitMessage(0);
            return TRUE;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR cmd, int show) {
    hInst = hInstance;

    secure_rand(ui_session_key, 32);

    OleInitialize(NULL);
    InitCommonControls();

    HWND hwnd = CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc);
    if (!hwnd) return 0;
    ShowWindow(hwnd, show);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
      
    OleUninitialize();
    return (int)msg.wParam;
}