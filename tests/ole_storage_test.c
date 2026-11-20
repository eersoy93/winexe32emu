/*
Copyright 2026 Erdem Ersoy (eersoy93)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
OLE storage test - the ole32, gdi32, user32 and kernel32 APIs Microsoft
Word 95 needs: compound files (IStorage, IStream), streams on global
memory, monikers and the running object table, the OLE clipboard, window
and viewport origins, regions, DIB sections and DOS device names.
Every check prints PASS or FAIL; the exit code is the failure count.
*/

#define COBJMACROS
#include <windows.h>
#include <ole2.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define DOCFILE L"C:\\Windows\\Temp\\ole_storage_test.doc"

static const CLSID CLSID_Test =
    {0x12345678, 0x1234, 0x5678, {0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78}};

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static void test_docfile(void)
{
    IStorage *root = NULL, *sub = NULL;
    IStream *stream = NULL;
    char buffer[32] = {0};
    ULONG done = 0;
    LARGE_INTEGER zero = {{0, 0}};
    STATSTG stat;
    CLSID clsid;
    CLIPFORMAT cf = 0;
    LPOLESTR user_type = NULL;
    UINT custom = RegisterClipboardFormatA("Test Object Format");

    HRESULT hr = StgCreateDocfile(DOCFILE, STGM_CREATE | STGM_READWRITE |
                                  STGM_SHARE_EXCLUSIVE, 0, &root);
    check(hr == S_OK && root, "StgCreateDocfile");
    if (!root)
        return;
    check(WriteClassStg(root, &CLSID_Test) == S_OK, "WriteClassStg");
    hr = IStorage_CreateStream(root, L"Data", STGM_CREATE | STGM_READWRITE |
                               STGM_SHARE_EXCLUSIVE, 0, 0, &stream);
    check(hr == S_OK && stream, "IStorage::CreateStream");
    check(IStream_Write(stream, "hello world", 11, &done) == S_OK && done == 11,
          "IStream::Write");
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    check(IStream_Read(stream, buffer, sizeof(buffer), &done) == S_OK && done == 11 &&
          !memcmp(buffer, "hello world", 11), "IStream::Read");
    check(IStream_Stat(stream, &stat, STATFLAG_NONAME) == S_OK &&
          stat.cbSize.QuadPart == 11 && stat.type == STGTY_STREAM, "IStream::Stat");
    IStream_Release(stream);
    check(IStorage_CreateStream(root, L"Data", STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0,
                                &stream) == STG_E_FILEALREADYEXISTS, "CreateStream twice");

    hr = IStorage_CreateStorage(root, L"Sub", STGM_CREATE | STGM_READWRITE |
                                STGM_SHARE_EXCLUSIVE, 0, 0, &sub);
    check(hr == S_OK && sub, "IStorage::CreateStorage");
    if (sub) {
        check(SetConvertStg(sub, TRUE) == S_OK && GetConvertStg(sub) == S_OK,
              "SetConvertStg/GetConvertStg");
        check(WriteFmtUserTypeStg(sub, (CLIPFORMAT)custom, L"Test Object") == S_OK,
              "WriteFmtUserTypeStg");
        check(ReadFmtUserTypeStg(sub, &cf, &user_type) == S_OK && cf == custom &&
              user_type && !wcscmp(user_type, L"Test Object"), "ReadFmtUserTypeStg");
        CoTaskMemFree(user_type);
        IStorage_Release(sub);
    }
    check(IStorage_Commit(root, STGC_DEFAULT) == S_OK, "IStorage::Commit");
    IStorage_Release(root);
    root = NULL;

    check(StgIsStorageFile(DOCFILE) == S_OK, "StgIsStorageFile");
    hr = StgOpenStorage(DOCFILE, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0, &root);
    check(hr == S_OK && root, "StgOpenStorage");
    if (!root)
        return;
    check(ReadClassStg(root, &clsid) == S_OK && IsEqualCLSID(&clsid, &CLSID_Test),
          "ReadClassStg after reopening");
    {
        IEnumSTATSTG *items = NULL;
        int count = 0;
        if (IStorage_EnumElements(root, 0, NULL, 0, &items) == S_OK) {
            while (IEnumSTATSTG_Next(items, 1, &stat, NULL) == S_OK) {
                count++;
                CoTaskMemFree(stat.pwcsName);
            }
            IEnumSTATSTG_Release(items);
        }
        check(count == 2, "IStorage::EnumElements");
    }
    memset(buffer, 0, sizeof(buffer));
    hr = IStorage_OpenStream(root, L"Data", NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, 0, &stream);
    check(hr == S_OK && IStream_Read(stream, buffer, 11, &done) == S_OK &&
          !memcmp(buffer, "hello world", 11), "the stream after reopening");
    if (stream) {
        check(IStream_Write(stream, "x", 1, &done) == STG_E_ACCESSDENIED,
              "a read-only stream refuses writes");
        IStream_Release(stream);
    }
    check(IStorage_OpenStream(root, L"Missing", NULL, STGM_READ | STGM_SHARE_EXCLUSIVE, 0,
                              &stream) == STG_E_FILENOTFOUND, "a missing stream");
    IStorage_Release(root);
    DeleteFileW(DOCFILE);

    {
        WCHAR self[MAX_PATH];
        GetModuleFileNameW(NULL, self, MAX_PATH);
        check(StgOpenStorage(self, NULL, STGM_READ | STGM_SHARE_DENY_WRITE, NULL, 0,
                             &root) == STG_E_FILEALREADYEXISTS, "a file that is no docfile");
    }
}

static void test_hglobal_stream(void)
{
    IStream *stream = NULL;
    HGLOBAL global = NULL;
    char data[1000];
    CLSID clsid;
    LARGE_INTEGER zero = {{0, 0}};
    int i;

    for (i = 0; i < (int)sizeof(data); i++)
        data[i] = (char)i;
    check(CreateStreamOnHGlobal(NULL, TRUE, &stream) == S_OK && stream,
          "CreateStreamOnHGlobal");
    if (!stream)
        return;
    IStream_Write(stream, data, sizeof(data), NULL);
    check(GetHGlobalFromStream(stream, &global) == S_OK && global &&
          GlobalSize(global) >= sizeof(data) && !memcmp(GlobalLock(global), data, sizeof(data)),
          "GetHGlobalFromStream holds the bytes");
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    check(WriteClassStm(stream, &CLSID_Test) == S_OK, "WriteClassStm");
    IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    check(ReadClassStm(stream, &clsid) == S_OK && IsEqualCLSID(&clsid, &CLSID_Test),
          "ReadClassStm");
    IStream_Release(stream);
}

static void test_monikers(void)
{
    IMoniker *file = NULL, *item = NULL, *composite = NULL, *parsed = NULL;
    IBindCtx *bind = NULL;
    IRunningObjectTable *table = NULL;
    IStream *object = NULL;
    IUnknown *found = NULL;
    LPOLESTR name = NULL;
    ULONG eaten = 0;
    DWORD cookie = 0;

    check(CreateFileMoniker(L"C:\\Docs\\Report.doc", &file) == S_OK, "CreateFileMoniker");
    check(CreateItemMoniker(L"!", L"Chart1", &item) == S_OK, "CreateItemMoniker");
    check(CreateGenericComposite(file, item, &composite) == S_OK, "CreateGenericComposite");
    check(CreateBindCtx(0, &bind) == S_OK, "CreateBindCtx");
    if (!composite || !bind)
        return;
    check(IMoniker_GetDisplayName(composite, bind, NULL, &name) == S_OK && name &&
          !wcscmp(name, L"C:\\Docs\\Report.doc!Chart1"), "IMoniker::GetDisplayName");
    CoTaskMemFree(name);
    check(MkParseDisplayName(bind, L"C:\\Docs\\Report.doc!Chart1", &eaten, &parsed) == S_OK &&
          eaten == 25 && IMoniker_IsEqual(parsed, composite) == S_OK, "MkParseDisplayName");

    CreateStreamOnHGlobal(NULL, TRUE, &object);
    check(GetRunningObjectTable(0, &table) == S_OK && table, "GetRunningObjectTable");
    if (table && object) {
        check(IRunningObjectTable_Register(table, 0, (IUnknown *)object, composite,
                                           &cookie) == S_OK, "IRunningObjectTable::Register");
        check(IRunningObjectTable_IsRunning(table, parsed) == S_OK, "a registered moniker runs");
        check(IRunningObjectTable_GetObject(table, parsed, &found) == S_OK &&
              found == (IUnknown *)object, "IRunningObjectTable::GetObject");
        if (found)
            IUnknown_Release(found);
        check(IRunningObjectTable_Revoke(table, cookie) == S_OK &&
              IRunningObjectTable_IsRunning(table, parsed) == S_FALSE,
              "IRunningObjectTable::Revoke");
        IRunningObjectTable_Release(table);
    }
    if (object)
        IStream_Release(object);
    IMoniker_Release(parsed);
    IMoniker_Release(composite);
    IMoniker_Release(item);
    IMoniker_Release(file);
    IBindCtx_Release(bind);
}

static void test_clipboard(void)
{
    IDataObject *data = NULL;
    FORMATETC format = {CF_TEXT, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM medium;
    HGLOBAL text = GlobalAlloc(GMEM_MOVEABLE, 4);

    memcpy(GlobalLock(text), "abc", 4);
    GlobalUnlock(text);
    OpenClipboard(NULL);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, text);
    CloseClipboard();
    check(OleGetClipboard(&data) == S_OK && data, "OleGetClipboard");
    if (!data)
        return;
    check(IDataObject_QueryGetData(data, &format) == S_OK, "IDataObject::QueryGetData");
    check(IDataObject_GetData(data, &format, &medium) == S_OK &&
          medium.tymed == TYMED_HGLOBAL && !strcmp(GlobalLock(medium.hGlobal), "abc"),
          "IDataObject::GetData");
    ReleaseStgMedium(&medium);
    check(OleIsCurrentClipboard(data) == S_FALSE, "OleIsCurrentClipboard");
    IDataObject_Release(data);
    check(OleSetClipboard(NULL) == S_OK, "OleSetClipboard(NULL)");
}

static void test_gdi(void)
{
    HDC dc = CreateCompatibleDC(NULL);
    POINT point = {0, 0}, triangle[3] = {{0, 0}, {10, 0}, {0, 10}};
    HRGN region;
    RECT box;
    LOGFONTA font;
    void *bits = NULL;
    BITMAPINFO info;
    HBITMAP section;
    BITMAP bitmap;

    SetViewportOrgEx(dc, 10, 20, NULL);
    LPtoDP(dc, &point, 1);
    check(point.x == 10 && point.y == 20, "SetViewportOrgEx moves LPtoDP");
    SetMapMode(dc, MM_ANISOTROPIC);
    SetViewportOrgEx(dc, 0, 0, NULL);
    SetWindowExtEx(dc, 100, 100, NULL);
    SetViewportExtEx(dc, 50, 50, NULL);
    point.x = point.y = 40;
    LPtoDP(dc, &point, 1);
    check(point.x == 20 && point.y == 20, "MM_ANISOTROPIC extents scale LPtoDP");

    region = CreatePolygonRgn(triangle, 3, ALTERNATE);
    /* The pixel rows inside; the bottom row's pixel lies on the edge */
    check(region && GetRgnBox(region, &box) != ERROR && box.left == 0 && box.top == 0 &&
          box.right == 10 && box.bottom >= 9 && box.bottom <= 10, "CreatePolygonRgn");
    OffsetRgn(region, 5, 5);
    GetRgnBox(region, &box);
    check(box.left == 5 && box.top == 5, "OffsetRgn");
    DeleteObject(region);

    check(GetObjectType(GetStockObject(SYSTEM_FONT)) == OBJ_FONT &&
          GetObjectA(GetStockObject(SYSTEM_FONT), sizeof(font), &font) > 0,
          "the SYSTEM_FONT stock object is a font");

    memset(&info, 0, sizeof(info));
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = 4;
    info.bmiHeader.biHeight = 4;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    section = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &bits, NULL, 0);
    check(section && bits && GetObjectA(section, sizeof(bitmap), &bitmap) &&
          bitmap.bmWidth == 4, "CreateDIBSection");
    check(GetObjectType(dc) == OBJ_MEMDC, "GetObjectType of a memory DC");
    DeleteObject(section);
    DeleteDC(dc);
}

static void test_kernel32(void)
{
    char target[64] = "";
    char self[MAX_PATH];
    DWORD type = 99;

    check(QueryDosDeviceA("C:", target, sizeof(target)) &&
          !strcmp(target, "\\Device\\HarddiskVolume1"), "QueryDosDeviceA");
    GetModuleFileNameA(NULL, self, sizeof(self));
    check(GetBinaryTypeA(self, &type) && type == SCS_32BIT_BINARY, "GetBinaryTypeA");
    check(OleBuildVersion() != 0, "OleBuildVersion");
}

int main(void)
{
    CLSID treat;

    OleInitialize(NULL);
    test_docfile();
    test_hglobal_stream();
    test_monikers();
    test_clipboard();
    test_gdi();
    test_kernel32();
    check(CoGetTreatAsClass(&CLSID_Test, &treat) == S_FALSE && IsEqualCLSID(&treat, &CLSID_Test),
          "CoGetTreatAsClass of a class without TreatAs");
    OleUninitialize();
    printf("== %d failure(s) ==\n", failures);
    return failures;
}
