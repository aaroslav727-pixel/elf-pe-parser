// binsec GUI: native Win32 front-end over binsec_lib (no external libraries).
// Open a file (button, Ctrl+O, drag-and-drop or command line), pick a view,
// optionally switch to JSON, save the report (Ctrl+S).
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "binsec/binary.hpp"
#include "binsec/report.hpp"
#include "binsec/version.hpp"

namespace {

enum : int {
  ID_OPEN = 101,
  ID_SAVE,
  ID_VIEW_CHECKSEC,
  ID_VIEW_SECTIONS,
  ID_VIEW_SYMBOLS,
  ID_VIEW_ALL,
  ID_JSON,
  ID_OUTPUT,
};
constexpr int kViews = 4;
constexpr wchar_t kClassName[] = L"BinsecMainWindow";

struct State {
  HWND window = nullptr;
  HWND output = nullptr;
  HWND save = nullptr;
  HWND views[kViews] = {};
  HWND json = nullptr;
  std::vector<HWND> toolbar;
  HFONT ui_font = nullptr;
  HFONT mono_font = nullptr;
  HBRUSH output_brush = nullptr;
  int dpi = 96;
  std::wstring path;
  std::optional<binsec::Result<binsec::Binary>> parsed;
  std::string report;  // last rendered report, LF line endings
} g;

int scale(int px) { return MulDiv(px, g.dpi, 96); }

std::string to_utf8(const std::wstring& w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(static_cast<std::size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring to_wide(const std::string& s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<std::size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::string crlf(const std::string& s) {
  std::string r;
  r.reserve(s.size() + s.size() / 16);
  for (char c : s) {
    if (c == '\n') r += '\r';
    r += c;
  }
  return r;
}

bool json_mode() { return SendMessageW(g.json, BM_GETCHECK, 0, 0) == BST_CHECKED; }

int current_view() {
  for (int i = 0; i < kViews; ++i)
    if (SendMessageW(g.views[i], BM_GETCHECK, 0, 0) == BST_CHECKED) return i;
  return 0;
}

void render() {
  if (!g.parsed) {
    SetWindowTextW(g.output,
                   L"Drop an ELF or PE file here, or click \"Open file...\" (Ctrl+O).\r\n\r\n"
                   L"binsec parses ELF (32/64-bit, little/big-endian) and PE (PE32/PE32+) binaries and audits\r\n"
                   L"their exploit mitigations: RELRO, PIE, NX, stack canary, FORTIFY, RPATH/RUNPATH for ELF;\r\n"
                   L"ASLR, High-Entropy VA, DEP, CFG, SafeSEH, /GS and Authenticode for PE.");
    EnableWindow(g.save, FALSE);
    return;
  }
  binsec::ReportOptions opt;
  switch (current_view()) {
    case 0: opt.checksec = true; break;
    case 1: opt.sections = true; break;
    case 2: opt.symbols = true; break;
    default: opt.all = true; break;
  }
  const std::string path = to_utf8(g.path);
  const auto& r = *g.parsed;
  if (!r) {
    g.report = json_mode() ? binsec::render_error_json(r.error(), path)
                           : "Cannot analyse " + path + "\n\nError (" + std::string(error_code_name(r.error().code)) +
                                 "): " + r.error().message + "\n";
  } else {
    g.report = json_mode() ? binsec::render_json(*r, path, opt) : binsec::render_text(*r, path, opt);
  }
  SetWindowTextW(g.output, to_wide(crlf(g.report)).c_str());
  EnableWindow(g.save, TRUE);
}

void load(const std::wstring& path) {
  std::ifstream in(std::filesystem::path(path), std::ios::binary);
  if (!in) {
    MessageBoxW(g.window, (L"Cannot open file:\n" + path).c_str(), L"binsec", MB_ICONERROR | MB_OK);
    return;
  }
  const std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  g.path = path;
  g.parsed.emplace(binsec::parse_binary(data));
  SetWindowTextW(g.window, (L"binsec - " + std::filesystem::path(path).filename().wstring()).c_str());
  render();
}

void open_dialog() {
  std::wstring buf(32768, L'\0');
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof ofn;
  ofn.hwndOwner = g.window;
  ofn.lpstrFilter = L"All files (*.*)\0*.*\0Windows binaries (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0"
                    L"ELF files (*.so;*.elf;*.o)\0*.so;*.so.*;*.elf;*.o\0";
  ofn.lpstrFile = buf.data();
  ofn.nMaxFile = static_cast<DWORD>(buf.size());
  ofn.lpstrTitle = L"Open ELF or PE binary";
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
  if (GetOpenFileNameW(&ofn)) load(buf.c_str());
}

void save_dialog() {
  if (g.report.empty()) return;
  const bool json = json_mode();
  std::wstring buf = std::filesystem::path(g.path).filename().wstring() + (json ? L".json" : L".txt");
  buf.resize(32768, L'\0');
  OPENFILENAMEW ofn{};
  ofn.lStructSize = sizeof ofn;
  ofn.hwndOwner = g.window;
  ofn.lpstrFilter = json ? L"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0" : L"Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0";
  ofn.lpstrDefExt = json ? L"json" : L"txt";
  ofn.lpstrFile = buf.data();
  ofn.nMaxFile = static_cast<DWORD>(buf.size());
  ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
  if (!GetSaveFileNameW(&ofn)) return;
  const std::string out = json ? g.report : crlf(g.report);
  std::ofstream f(std::filesystem::path(buf.c_str()), std::ios::binary);
  f.write(out.data(), static_cast<std::streamsize>(out.size()));
  if (!f) MessageBoxW(g.window, L"Could not write the report.", L"binsec", MB_ICONERROR | MB_OK);
}

HWND make(const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex_style = 0) {
  HWND h = CreateWindowExW(ex_style, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, g.window,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
  SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(id == ID_OUTPUT ? g.mono_font : g.ui_font), TRUE);
  return h;
}

void create_fonts() {
  NONCLIENTMETRICSW ncm{};
  ncm.cbSize = sizeof ncm;
  SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
  g.ui_font = CreateFontIndirectW(&ncm.lfMessageFont);
  g.mono_font = CreateFontW(-MulDiv(10, g.dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
                            L"Consolas");
}

void create_controls() {
  create_fonts();
  g.toolbar.push_back(make(L"BUTTON", L"Open file...", BS_PUSHBUTTON | WS_TABSTOP, ID_OPEN));
  g.save = make(L"BUTTON", L"Save report...", BS_PUSHBUTTON | WS_TABSTOP, ID_SAVE);
  g.toolbar.push_back(g.save);
  const wchar_t* names[kViews] = {L"Checksec", L"Sections", L"Symbols / imports", L"All"};
  for (int i = 0; i < kViews; ++i) {
    g.views[i] = make(L"BUTTON", names[i], BS_AUTORADIOBUTTON | (i == 0 ? WS_GROUP | WS_TABSTOP : 0), ID_VIEW_CHECKSEC + i);
    g.toolbar.push_back(g.views[i]);
  }
  SendMessageW(g.views[0], BM_SETCHECK, BST_CHECKED, 0);
  g.json = make(L"BUTTON", L"JSON", BS_AUTOCHECKBOX | WS_GROUP | WS_TABSTOP, ID_JSON);
  g.toolbar.push_back(g.json);
  g.output = make(L"EDIT", L"",
                  WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_TABSTOP,
                  ID_OUTPUT, WS_EX_CLIENTEDGE);
  SendMessageW(g.output, EM_SETLIMITTEXT, 0, 0);  // multi-line edit: lift the 32 KiB default
  g.output_brush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
}

void layout(int width, int height) {
  const int pad = scale(8), h = scale(28);
  const int widths[] = {scale(104), scale(112), scale(88), scale(84), scale(136), scale(48), scale(64)};
  int x = pad;
  for (std::size_t i = 0; i < g.toolbar.size(); ++i) {
    if (i == 2 || i == 6) x += scale(12);  // gaps between button / view / JSON groups
    MoveWindow(g.toolbar[i], x, pad, widths[i], h, TRUE);
    x += widths[i] + scale(4);
  }
  const int top = pad * 2 + h;
  MoveWindow(g.output, pad, top, width - 2 * pad, height - top - pad, TRUE);
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_CREATE:
      g.window = hwnd;
      create_controls();
      DragAcceptFiles(hwnd, TRUE);
      render();
      return 0;
    case WM_SIZE:
      layout(LOWORD(lp), HIWORD(lp));
      return 0;
    case WM_GETMINMAXINFO: {
      auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
      mmi->ptMinTrackSize = {scale(720), scale(320)};
      return 0;
    }
    case WM_COMMAND:
      switch (LOWORD(wp)) {
        case ID_OPEN: open_dialog(); return 0;
        case ID_SAVE: save_dialog(); return 0;
        case ID_VIEW_CHECKSEC:
        case ID_VIEW_SECTIONS:
        case ID_VIEW_SYMBOLS:
        case ID_VIEW_ALL:
        case ID_JSON:
          if (HIWORD(wp) == BN_CLICKED) render();
          return 0;
      }
      break;
    case WM_DROPFILES: {
      auto drop = reinterpret_cast<HDROP>(wp);
      const UINT len = DragQueryFileW(drop, 0, nullptr, 0);
      std::wstring path(len + 1, L'\0');
      DragQueryFileW(drop, 0, path.data(), len + 1);
      path.resize(len);
      DragFinish(drop);
      load(path);
      SetForegroundWindow(hwnd);
      return 0;
    }
    case WM_CTLCOLORSTATIC:  // read-only edit: keep a normal window background
      if (reinterpret_cast<HWND>(lp) == g.output) {
        auto dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, GetSysColor(COLOR_WINDOW));
        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
        return reinterpret_cast<LRESULT>(g.output_brush);
      }
      break;
    case WM_DESTROY:
      DeleteObject(g.ui_font);
      DeleteObject(g.mono_font);
      DeleteObject(g.output_brush);
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int show) {
  INITCOMMONCONTROLSEX icc{sizeof icc, ICC_STANDARD_CLASSES};
  InitCommonControlsEx(&icc);
  {
    HDC screen = GetDC(nullptr);
    g.dpi = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(nullptr, screen);
  }

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof wc;
  wc.lpfnWndProc = wnd_proc;
  wc.hInstance = instance;
  wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
  wc.hIconSm = wc.hIcon;
  wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));  // IDC_ARROW
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  wc.lpszClassName = kClassName;
  RegisterClassExW(&wc);

  const std::wstring title = L"binsec " + to_wide(std::string(binsec::version())) + L" - ELF/PE checksec";
  HWND hwnd = CreateWindowExW(WS_EX_ACCEPTFILES, kClassName, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                              CW_USEDEFAULT, scale(1000), scale(680), nullptr, nullptr, instance, nullptr);
  if (!hwnd) return 1;
  ShowWindow(hwnd, show);
  UpdateWindow(hwnd);

  // "binsec-gui.exe <file>" (also used by Explorer's "Open with")
  int argc = 0;
  if (LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
    if (argc > 1) load(argv[1]);
    LocalFree(argv);
  }

  ACCEL keys[] = {{FCONTROL | FVIRTKEY, 'O', ID_OPEN}, {FCONTROL | FVIRTKEY, 'S', ID_SAVE}};
  HACCEL accel = CreateAcceleratorTableW(keys, 2);
  MSG m;
  while (GetMessageW(&m, nullptr, 0, 0) > 0) {
    if (TranslateAcceleratorW(hwnd, accel, &m)) continue;
    if (IsDialogMessageW(hwnd, &m)) continue;  // Tab between controls
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  DestroyAcceleratorTable(accel);
  return static_cast<int>(m.wParam);
}
