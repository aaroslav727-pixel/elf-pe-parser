// Synthesises small but structurally complete ELF images for tests:
// header, program headers, .interp/.dynstr/.dynsym/.dynamic/.strtab/.symtab/.shstrtab.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "binsec/elf.hpp"

namespace testelf {

struct Spec {
  bool is64 = true;
  bool big_endian = false;
  std::uint16_t type = binsec::elf::ET_DYN;
  std::uint16_t machine = 62;
  bool interp = true;
  bool gnu_relro = true;
  bool bind_now = true;
  bool gnu_stack = true;
  bool exec_stack = false;
  bool symtab = true;
  bool section_headers = true;
  std::uint64_t flags_1 = 0;
  std::vector<std::string> needed = {"libc.so.6"};
  std::vector<std::string> dynsyms = {"puts", "__stack_chk_fail", "__printf_chk"};
  std::string rpath;
  std::string runpath;
};

class Buf {
 public:
  explicit Buf(bool be) : be_(be) {}
  void put(std::size_t off, std::uint64_t v, unsigned width) {
    if (b_.size() < off + width) b_.resize(off + width);
    for (unsigned i = 0; i < width; ++i) b_[off + (be_ ? width - 1 - i : i)] = static_cast<std::uint8_t>(v >> (8 * i));
  }
  std::size_t append(const std::vector<std::uint8_t>& d, std::size_t align = 8) {
    while (b_.size() % align) b_.push_back(0);
    const std::size_t off = b_.size();
    b_.insert(b_.end(), d.begin(), d.end());
    return off;
  }
  std::size_t size() const { return b_.size(); }
  std::vector<std::uint8_t>& bytes() { return b_; }
  bool be() const { return be_; }

 private:
  std::vector<std::uint8_t> b_;
  bool be_;
};

struct StrTab {
  std::vector<std::uint8_t> d{0};
  std::uint32_t add(const std::string& s) {
    const auto off = static_cast<std::uint32_t>(d.size());
    d.insert(d.end(), s.begin(), s.end());
    d.push_back(0);
    return off;
  }
};

inline std::vector<std::uint8_t> build(const Spec& sp) {
  using namespace binsec::elf;
  const bool w = sp.is64;
  const unsigned W = w ? 8 : 4;
  const std::size_t ehsize = w ? 64 : 52, phent = w ? 56 : 32, shent = w ? 64 : 40;
  const std::size_t symsz = w ? 24 : 16, dynsz = w ? 16 : 8;
  const std::uint64_t base = sp.type == ET_EXEC ? 0x400000 : 0;

  std::size_t nph = 2;  // LOAD + DYNAMIC
  if (sp.interp) ++nph;
  if (sp.gnu_stack) ++nph;
  if (sp.gnu_relro) ++nph;

  Buf b(sp.big_endian);
  b.bytes().resize(ehsize + nph * phent);

  // --- payload blobs
  const std::string interp = "/lib64/ld-linux-x86-64.so.2";
  std::size_t interp_off = 0;
  if (sp.interp) {
    std::vector<std::uint8_t> v(interp.begin(), interp.end());
    v.push_back(0);
    interp_off = b.append(v, 1);
  }

  StrTab dynstr;
  std::vector<std::uint32_t> needed_off, dynsym_name;
  for (const auto& n : sp.needed) needed_off.push_back(dynstr.add(n));
  for (const auto& n : sp.dynsyms) dynsym_name.push_back(dynstr.add(n));
  const std::uint32_t rpath_off = sp.rpath.empty() ? 0 : dynstr.add(sp.rpath);
  const std::uint32_t runpath_off = sp.runpath.empty() ? 0 : dynstr.add(sp.runpath);
  const std::size_t dynstr_off = b.append(dynstr.d, 1);

  auto symbol_table = [&](const std::vector<std::uint32_t>& names, std::uint8_t info, std::uint16_t shndx) {
    Buf t(sp.big_endian);
    t.bytes().resize((names.size() + 1) * symsz);
    for (std::size_t i = 0; i < names.size(); ++i) {
      const std::size_t o = (i + 1) * symsz;
      t.put(o, names[i], 4);
      if (w) {
        t.put(o + 4, info, 1);
        t.put(o + 6, shndx, 2);
        t.put(o + 8, shndx ? 0x1000 + i * 16 : 0, 8);
        t.put(o + 16, shndx ? 16 : 0, 8);
      } else {
        t.put(o + 4, shndx ? 0x1000 + i * 16 : 0, 4);
        t.put(o + 8, shndx ? 16 : 0, 4);
        t.put(o + 12, info, 1);
        t.put(o + 14, shndx, 2);
      }
    }
    return t.bytes();
  };
  const std::size_t dynsym_off = b.append(symbol_table(dynsym_name, 0x12 /*GLOBAL FUNC*/, 0));
  const std::size_t dynsym_size = (sp.dynsyms.size() + 1) * symsz;

  std::vector<std::pair<std::int64_t, std::uint64_t>> dyn;
  for (auto off : needed_off) dyn.emplace_back(DT_NEEDED, off);
  if (!sp.rpath.empty()) dyn.emplace_back(DT_RPATH, rpath_off);
  if (!sp.runpath.empty()) dyn.emplace_back(DT_RUNPATH, runpath_off);
  dyn.emplace_back(DT_STRTAB, base + dynstr_off);
  dyn.emplace_back(DT_STRSZ, dynstr.d.size());
  dyn.emplace_back(DT_SYMTAB, base + dynsym_off);
  if (sp.bind_now) dyn.emplace_back(DT_FLAGS, DF_BIND_NOW);
  if (sp.bind_now || sp.flags_1) dyn.emplace_back(DT_FLAGS_1, (sp.bind_now ? DF_1_NOW : 0) | sp.flags_1);
  dyn.emplace_back(DT_NULL, 0);
  Buf dt(sp.big_endian);
  for (std::size_t i = 0; i < dyn.size(); ++i) {
    dt.put(i * dynsz, static_cast<std::uint64_t>(dyn[i].first), W);
    dt.put(i * dynsz + W, dyn[i].second, W);
  }
  const std::size_t dynamic_off = b.append(dt.bytes());
  const std::size_t dynamic_size = dyn.size() * dynsz;

  StrTab strtab;
  std::vector<std::uint32_t> local_names{strtab.add("main"), strtab.add("helper")};
  const std::size_t strtab_off = b.append(strtab.d, 1);
  std::size_t symtab_off = 0, symtab_size = 0;
  if (sp.symtab) {
    symtab_off = b.append(symbol_table(local_names, 0x12, 1));
    symtab_size = (local_names.size() + 1) * symsz;
  }

  StrTab shstr;
  struct Sh {
    std::uint32_t name, type;
    std::uint64_t flags, offset, size;
    std::uint32_t link;
    std::uint64_t entsize;
  };
  std::vector<Sh> sh;
  sh.push_back({0, SHT_NULL, 0, 0, 0, 0, 0});
  if (sp.interp) sh.push_back({shstr.add(".interp"), SHT_PROGBITS, SHF_ALLOC, interp_off, interp.size() + 1, 0, 0});
  const auto dynstr_idx = static_cast<std::uint32_t>(sh.size());
  sh.push_back({shstr.add(".dynstr"), SHT_STRTAB, SHF_ALLOC, dynstr_off, dynstr.d.size(), 0, 0});
  sh.push_back({shstr.add(".dynsym"), SHT_DYNSYM, SHF_ALLOC, dynsym_off, dynsym_size, dynstr_idx, symsz});
  sh.push_back({shstr.add(".dynamic"), SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynamic_off, dynamic_size, dynstr_idx,
                dynsz});
  const auto strtab_idx = static_cast<std::uint32_t>(sh.size());
  sh.push_back({shstr.add(".strtab"), SHT_STRTAB, 0, strtab_off, strtab.d.size(), 0, 0});
  if (sp.symtab) sh.push_back({shstr.add(".symtab"), SHT_SYMTAB, 0, symtab_off, symtab_size, strtab_idx, symsz});
  const auto shstr_idx = static_cast<std::uint32_t>(sh.size());
  const std::uint32_t shstr_name = shstr.add(".shstrtab");
  const std::size_t shstr_off = b.append(shstr.d, 1);
  sh.push_back({shstr_name, SHT_STRTAB, 0, shstr_off, shstr.d.size(), 0, 0});

  std::size_t shoff = 0;
  if (sp.section_headers) {
    Buf t(sp.big_endian);
    t.bytes().resize(sh.size() * shent);
    for (std::size_t i = 0; i < sh.size(); ++i) {
      const std::size_t o = i * shent;
      const auto& s = sh[i];
      t.put(o, s.name, 4);
      t.put(o + 4, s.type, 4);
      t.put(o + 8, s.flags, W);
      t.put(o + 8 + W, (s.flags & SHF_ALLOC) ? base + s.offset : 0, W);
      t.put(o + 8 + 2 * W, s.offset, W);
      t.put(o + 8 + 3 * W, s.size, W);
      t.put(o + 8 + 4 * W, s.link, 4);
      t.put(o + 12 + 4 * W, 0, 4);
      t.put(o + 16 + 4 * W, 1, W);
      t.put(o + 16 + 5 * W, s.entsize, W);
    }
    shoff = b.append(t.bytes());
  }
  const std::size_t total = b.size();

  // --- program headers
  std::size_t ph = ehsize;
  auto phdr = [&](std::uint32_t type, std::uint32_t flags, std::uint64_t off, std::uint64_t size) {
    b.put(ph, type, 4);
    if (w) {
      b.put(ph + 4, flags, 4);
      b.put(ph + 8, off, 8);
      b.put(ph + 16, base + off, 8);
      b.put(ph + 24, base + off, 8);
      b.put(ph + 32, size, 8);
      b.put(ph + 40, size, 8);
      b.put(ph + 48, type == PT_LOAD ? 0x1000 : 8, 8);
    } else {
      b.put(ph + 4, off, 4);
      b.put(ph + 8, base + off, 4);
      b.put(ph + 12, base + off, 4);
      b.put(ph + 16, size, 4);
      b.put(ph + 20, size, 4);
      b.put(ph + 24, flags, 4);
      b.put(ph + 28, type == PT_LOAD ? 0x1000 : 4, 4);
    }
    ph += phent;
  };
  phdr(PT_LOAD, PF_R | PF_W | PF_X, 0, total);
  if (sp.interp) phdr(PT_INTERP, PF_R, interp_off, interp.size() + 1);
  phdr(PT_DYNAMIC, PF_R | PF_W, dynamic_off, dynamic_size);
  if (sp.gnu_stack) phdr(PT_GNU_STACK, PF_R | PF_W | (sp.exec_stack ? PF_X : 0), 0, 0);
  if (sp.gnu_relro) phdr(PT_GNU_RELRO, PF_R, dynamic_off, dynamic_size);

  // --- ELF header
  auto& v = b.bytes();
  v[0] = 0x7f, v[1] = 'E', v[2] = 'L', v[3] = 'F';
  v[4] = w ? 2 : 1;
  v[5] = sp.big_endian ? 2 : 1;
  v[6] = 1;
  b.put(16, sp.type, 2);
  b.put(18, sp.machine, 2);
  b.put(20, 1, 4);
  b.put(24, base + 0x1000, W);
  b.put(24 + W, ehsize, W);                      // e_phoff
  b.put(24 + 2 * W, shoff, W);                   // e_shoff
  b.put(24 + 3 * W + 4, ehsize, 2);              // e_ehsize
  b.put(24 + 3 * W + 6, phent, 2);               // e_phentsize
  b.put(24 + 3 * W + 8, nph, 2);                 // e_phnum
  b.put(24 + 3 * W + 10, shent, 2);              // e_shentsize
  b.put(24 + 3 * W + 12, sp.section_headers ? sh.size() : 0, 2);  // e_shnum
  b.put(24 + 3 * W + 14, sp.section_headers ? shstr_idx : 0, 2);  // e_shstrndx
  return v;
}

}  // namespace testelf
