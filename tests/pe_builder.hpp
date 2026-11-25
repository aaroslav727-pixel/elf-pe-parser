// Synthesises small PE32 / PE32+ images for tests: DOS + PE headers, .text,
// .rdata with import/export/load-config directories, optional certificate blob.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "binsec/pe.hpp"
#include "elf_builder.hpp"  // testelf::Buf

namespace testpe {

struct Spec {
  bool pe32_plus = true;
  bool dll = false;
  std::uint16_t dll_characteristics = binsec::pe::DLL_DYNAMIC_BASE | binsec::pe::DLL_HIGH_ENTROPY_VA |
                                      binsec::pe::DLL_NX_COMPAT | binsec::pe::DLL_GUARD_CF;
  bool load_config = true;
  std::uint64_t security_cookie = 0x3000;
  bool seh_table = false;  // PE32 only
  bool certificate = false;
  std::vector<std::pair<std::string, std::vector<std::string>>> imports = {
      {"KERNEL32.dll", {"ExitProcess", "GetStdHandle", "#17"}}, {"msvcrt.dll", {"printf"}}};
  std::vector<std::string> exports;  // non-empty -> export directory for "test.dll"
};

inline std::vector<std::uint8_t> build(const Spec& sp) {
  namespace pe = binsec::pe;
  const bool w = sp.pe32_plus;
  const unsigned T = w ? 8 : 4;
  constexpr std::uint32_t kRdataRva = 0x2000, kRdataRaw = 0x400;

  // ---- .rdata payload
  testelf::Buf rd(false);
  auto alloc = [&](std::size_t n) {
    const std::size_t off = rd.size();
    rd.bytes().resize(off + n);
    return off;
  };
  auto put_str = [&](const std::string& s) {
    const std::size_t off = alloc(s.size() + 1);
    std::memcpy(rd.bytes().data() + off, s.data(), s.size());
    return off;
  };
  auto rva = [&](std::size_t off) { return kRdataRva + static_cast<std::uint32_t>(off); };

  std::uint32_t imp_rva = 0, imp_size = 0, exp_rva = 0, exp_size = 0, lc_rva = 0, lc_size = 0;
  if (!sp.imports.empty()) {
    const std::size_t dir = alloc((sp.imports.size() + 1) * 20);
    imp_rva = rva(dir);
    imp_size = static_cast<std::uint32_t>((sp.imports.size() + 1) * 20);
    for (std::size_t i = 0; i < sp.imports.size(); ++i) {
      const auto& [dll, fns] = sp.imports[i];
      const std::size_t int_tab = alloc((fns.size() + 1) * T);
      const std::size_t iat = alloc((fns.size() + 1) * T);
      const std::size_t name = put_str(dll);
      for (std::size_t j = 0; j < fns.size(); ++j) {
        std::uint64_t v;
        if (fns[j][0] == '#') {
          v = (w ? (1ull << 63) : (1ull << 31)) | std::stoul(fns[j].substr(1));
        } else {
          const std::size_t hint = alloc(2);
          put_str(fns[j]);
          v = rva(hint);
        }
        rd.put(int_tab + j * T, v, T);
        rd.put(iat + j * T, v, T);
      }
      rd.put(dir + i * 20, rva(int_tab), 4);
      rd.put(dir + i * 20 + 12, rva(name), 4);
      rd.put(dir + i * 20 + 16, rva(iat), 4);
    }
  }
  if (!sp.exports.empty()) {
    const std::size_t n = sp.exports.size();
    const std::size_t dir = alloc(40), funcs = alloc(4 * n), names = alloc(4 * n), ords = alloc(2 * n);
    const std::size_t dllname = put_str("test.dll");
    for (std::size_t i = 0; i < n; ++i) {
      const std::size_t nm = put_str(sp.exports[i]);
      rd.put(funcs + 4 * i, 0x1000 + 16 * i, 4);
      rd.put(names + 4 * i, rva(nm), 4);
      rd.put(ords + 2 * i, i, 2);
    }
    rd.put(dir + 12, rva(dllname), 4);
    rd.put(dir + 16, 1, 4);  // ordinal base
    rd.put(dir + 20, n, 4);
    rd.put(dir + 24, n, 4);
    rd.put(dir + 28, rva(funcs), 4);
    rd.put(dir + 32, rva(names), 4);
    rd.put(dir + 36, rva(ords), 4);
    exp_rva = rva(dir);
    exp_size = static_cast<std::uint32_t>(rd.size() - dir);
  }
  if (sp.load_config) {
    lc_size = w ? 148 : 92;
    const std::size_t lc = alloc(lc_size);
    lc_rva = rva(lc);
    rd.put(lc, lc_size, 4);
    rd.put(lc + (w ? 88 : 60), sp.security_cookie, T);
    if (sp.seh_table && !w) {
      rd.put(lc + 64, 0x00402000, 4);
      rd.put(lc + 68, 2, 4);
    }
  }
  const std::size_t rd_used = rd.size();
  rd.bytes().resize((rd_used + 0x1ff) & ~std::size_t{0x1ff});

  // ---- headers
  const std::uint32_t fixed = w ? 112 : 96, opt_size = fixed + 16 * 8;
  testelf::Buf img(false);
  img.bytes().resize(kRdataRaw + rd.size());
  auto& b = img.bytes();
  b[0] = 'M', b[1] = 'Z';
  img.put(0x3c, 0x80, 4);
  img.put(0x80, 0x4550, 4);
  const std::size_t coff = 0x84, opt = 0x98;
  img.put(coff, w ? 0x8664 : 0x14c, 2);
  img.put(coff + 2, 2, 2);  // sections
  img.put(coff + 4, 0x60000000, 4);
  img.put(coff + 16, opt_size, 2);
  img.put(coff + 18, pe::FILE_EXECUTABLE_IMAGE | (sp.dll ? pe::FILE_DLL : 0) | (w ? pe::FILE_LARGE_ADDRESS_AWARE : 0x100),
          2);
  img.put(opt, w ? pe::MAGIC_PE32_PLUS : pe::MAGIC_PE32, 2);
  img.put(opt + 4, 0x200, 4);    // SizeOfCode
  img.put(opt + 16, 0x1000, 4);  // AddressOfEntryPoint
  img.put(opt + 20, 0x1000, 4);  // BaseOfCode
  if (w) {
    img.put(opt + 24, 0x140000000ull, 8);
  } else {
    img.put(opt + 24, kRdataRva, 4);
    img.put(opt + 28, 0x400000, 4);
  }
  img.put(opt + 32, 0x1000, 4);  // SectionAlignment
  img.put(opt + 36, 0x200, 4);   // FileAlignment
  img.put(opt + 40, 6, 2);
  img.put(opt + 48, 6, 2);
  img.put(opt + 56, kRdataRva + ((rd.size() + 0xfff) & ~std::size_t{0xfff}), 4);  // SizeOfImage
  img.put(opt + 60, 0x200, 4);                                                    // SizeOfHeaders
  img.put(opt + 68, 3, 2);                                                        // Windows CUI
  img.put(opt + 70, sp.dll_characteristics, 2);
  img.put(opt + fixed - 4, 16, 4);  // NumberOfRvaAndSizes
  auto dir = [&](std::size_t idx, std::uint32_t r, std::uint32_t s) {
    img.put(opt + fixed + idx * 8, r, 4);
    img.put(opt + fixed + idx * 8 + 4, s, 4);
  };
  dir(pe::DIR_EXPORT, exp_rva, exp_size);
  dir(pe::DIR_IMPORT, imp_rva, imp_size);
  dir(pe::DIR_LOAD_CONFIG, lc_rva, lc_size);

  auto section = [&](std::size_t idx, const char* name, std::uint32_t vsize, std::uint32_t va, std::uint32_t rsize,
                     std::uint32_t roff, std::uint32_t ch) {
    const std::size_t s = opt + opt_size + idx * 40;
    std::memcpy(b.data() + s, name, std::strlen(name));
    img.put(s + 8, vsize, 4);
    img.put(s + 12, va, 4);
    img.put(s + 16, rsize, 4);
    img.put(s + 20, roff, 4);
    img.put(s + 36, ch, 4);
  };
  section(0, ".text", 0x10, 0x1000, 0x200, 0x200, pe::SCN_CNT_CODE | pe::SCN_MEM_EXECUTE | pe::SCN_MEM_READ);
  section(1, ".rdata", static_cast<std::uint32_t>(rd_used), kRdataRva, static_cast<std::uint32_t>(rd.size()), kRdataRaw,
          pe::SCN_CNT_INITIALIZED_DATA | pe::SCN_MEM_READ);
  for (std::size_t i = 0x200; i < 0x210; ++i) b[i] = 0xc3;
  std::memcpy(b.data() + kRdataRaw, rd.bytes().data(), rd.size());

  if (sp.certificate) {
    const std::size_t off = img.size();
    img.put(off, 16, 4);       // dwLength
    img.put(off + 4, 0x200, 2);  // WIN_CERT_REVISION_2_0
    img.put(off + 6, 2, 2);      // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    img.put(off + 15, 0, 1);
    dir(pe::DIR_SECURITY, static_cast<std::uint32_t>(off), 16);
  }
  return img.bytes();
}

}  // namespace testpe
