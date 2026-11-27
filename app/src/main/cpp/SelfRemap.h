#pragma once

#include <cstdint>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
#include <vector>
#include <string>

namespace SelfRemap {
    struct MapEntry {
        uintptr_t start;
        uintptr_t end;
        int prot;
        std::string path;
    };

    static std::vector<MapEntry> CollectMatchingMaps(const std::string& include_substr,
                                                     const std::string& exclude_substr) {
        std::vector<MapEntry> result;
        FILE *fp = std::fopen("/proc/self/maps", "re");
        if (!fp) {
            return result;
        }

        char line[512];
        while (std::fgets(line, sizeof(line), fp)) {
            if (std::strstr(line, include_substr.c_str()) == nullptr) {
                continue;
            }
            if (!exclude_substr.empty() && std::strstr(line, exclude_substr.c_str()) != nullptr) {
                continue;
            }

            MapEntry entry{};
            char perms[12] = {0};
            char path[256] = {0};
            uintptr_t offset = 0;
            char dev[32] = {0};
            uint64_t inode = 0;

            int parsed = std::sscanf(
                line,
                "%" SCNxPTR "-%" SCNxPTR " %11s %" SCNxPTR " %31s %" SCNu64 " %255s",
                &entry.start, &entry.end, perms, &offset, dev, &inode, path
            );

            if (parsed >= 3 && entry.end > entry.start) {
                if (std::strchr(perms, 'r')) entry.prot |= PROT_READ;
                if (std::strchr(perms, 'w')) entry.prot |= PROT_WRITE;
                if (std::strchr(perms, 'x')) entry.prot |= PROT_EXEC;
                entry.path = path;
                result.push_back(entry);
            }
        }

        std::fclose(fp);
        return result;
    }

    __attribute__((noinline))
    static void RemapByFilter(const std::string& include_substr,
                              const std::string& exclude_substr = "") {
        std::vector<MapEntry> entries = CollectMatchingMaps(include_substr, exclude_substr);

        for (const auto& item : entries) {
            void *addr = reinterpret_cast<void *>(item.start);
            size_t size = static_cast<size_t>(item.end - item.start);
            if (size == 0) {
                continue;
            }

            void *backup = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (backup == MAP_FAILED) {
                continue;
            }

            if ((item.prot & PROT_READ) == 0) {
                mprotect(addr, size, item.prot | PROT_READ);
            }

            std::memcpy(backup, addr, size);

            if (munmap(addr, size) != 0) {
                munmap(backup, size);
                continue;
            }

            void *anon = mmap(addr, size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (anon == MAP_FAILED) {
                munmap(backup, size);
                continue;
            }

            std::memcpy(anon, backup, size);
            munmap(backup, size);

            __builtin___clear_cache(reinterpret_cast<char *>(anon),
                                    reinterpret_cast<char *>(anon) + size);

            if (item.prot != 0) {
                mprotect(anon, size, item.prot);
            }
        }
    }
}
