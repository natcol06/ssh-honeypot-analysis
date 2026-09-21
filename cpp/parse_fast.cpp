// parse_fast.cpp - C++ parser using simdjson
//
// Same report as parse.cpp, but parses JSON with simdjson instead of
// nlohmann/json. The first version spent about 98% of its time inside
// nlohmann's parser, which builds a full object for every line. simdjson's
// "On Demand" API skips that and only reads the fields you ask for.
//
// Build:  g++ -std=c++17 -O2 -static parse_fast.cpp simdjson.cpp -o parse_fast
// Run:    ./parse_fast            (reads ../data)
//         ./parse_fast some/dir   (reads another folder)

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "simdjson.h"

namespace fs = std::filesystem;
using namespace simdjson;
using Counter = std::unordered_map<std::string, int>;

// Find every Cowrie log in the folder, skipping the committed sample file
// so its lines are not counted twice.
std::vector<fs::path> find_logs(const fs::path& folder) {
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(folder)) {
        std::string name = entry.path().filename().string();
        bool is_log = name.find(".json") != std::string::npos;
        bool is_sample = name.rfind("sample", 0) == 0;  // starts with "sample"
        if (entry.is_regular_file() && is_log && !is_sample) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

std::string shorten(const std::string& s, size_t max_len = 60) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len - 3) + "...";
}

void print_top(const std::string& title, const Counter& counts, size_t n = 10) {
    std::vector<std::pair<std::string, int>> rows(counts.begin(), counts.end());
    size_t k = std::min(n, rows.size());
    std::partial_sort(rows.begin(), rows.begin() + k, rows.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });

    std::cout << "\n" << title << "\n";
    for (size_t i = 0; i < k; i++) {
        std::cout << "  " << std::setw(7) << rows[i].second << "  "
                  << shorten(rows[i].first) << "\n";
    }
}

// Read one string field. Returns an empty string if the field is missing
// or is not a string, so one odd event never stops the run.
//
// simdjson hands back a string_view that points into its own buffer,
// which gets reused for the next line. That is why the value is copied
// into a std::string before it goes into a map or set.
std::string field(ondemand::object& obj, const char* key) {
    std::string_view value;
    if (obj[key].get_string().get(value)) return "";
    return std::string(value);
}

int main(int argc, char* argv[]) {
    fs::path folder = (argc > 1) ? argv[1] : "../data";

    auto start = std::chrono::steady_clock::now();

    std::vector<fs::path> files = find_logs(folder);
    if (files.empty()) {
        std::cerr << "No .json logs found in " << folder << "\n";
        return 1;
    }

    Counter attempts_by_ip, usernames, passwords, commands;
    std::unordered_set<std::string> sessions;
    std::unordered_set<std::string> connected_hosts;

    long total_attempts = 0;
    long total_commands = 0;
    long bad_lines = 0;
    long lines_read = 0;

    ondemand::parser parser;  // reused for every line, so memory is allocated once

    for (const auto& path : files) {
        // Load the whole file at once. simdjson needs a few bytes of padding
        // past the end of the text so it can read in large chunks safely;
        // padded_string::load takes care of that.
        padded_string text;
        if (padded_string::load(path.string()).get(text)) {
            std::cerr << "Could not read " << path << "\n";
            continue;
        }

        // Walk the file line by line. Each line is parsed on its own so a
        // single broken line is skipped instead of ending the whole file.
        std::string_view all(text.data(), text.size());
        size_t pos = 0;
        while (pos < all.size()) {
            size_t end = all.find('\n', pos);
            if (end == std::string_view::npos) end = all.size();
            std::string_view line = all.substr(pos, end - pos);
            pos = end + 1;

            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty()) continue;
            lines_read++;

            // padded_string_view tells simdjson it may safely read a little
            // past the end of this line, which is true because the rest of
            // the file (and the padding) sits right after it in memory.
            size_t room = text.size() + SIMDJSON_PADDING - (line.data() - text.data());
            ondemand::document doc;
            ondemand::object event;
            if (parser.iterate(padded_string_view(line.data(), line.size(), room)).get(doc) ||
                doc.get_object().get(event)) {
                bad_lines++;
                continue;
            }

            std::string kind = field(event, "eventid");
            std::string ip = field(event, "src_ip");
            std::string session = field(event, "session");

            if (!session.empty()) sessions.insert(session);
            if (!ip.empty()) connected_hosts.insert(ip);

            if (kind == "cowrie.login.success" || kind == "cowrie.login.failed") {
                attempts_by_ip[ip]++;
                usernames[field(event, "username")]++;
                passwords[field(event, "password")]++;
                total_attempts++;
            } else if (kind == "cowrie.command.input") {
                commands[field(event, "input")]++;
                total_commands++;
            }
        }
    }

    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    std::cout << "SSH Honeypot Report (C++, simdjson)\n";
    std::cout << "===================================\n";
    std::cout << "Files read:          " << files.size() << "\n";
    std::cout << "Lines read:          " << lines_read << "\n";
    if (bad_lines) std::cout << "Skipped lines:       " << bad_lines << "\n";
    std::cout << "Sessions:            " << sessions.size() << "\n";
    std::cout << "Hosts connected:     " << connected_hosts.size() << "\n";
    std::cout << "Hosts tried a login: " << attempts_by_ip.size() << "\n";
    std::cout << "Login attempts:      " << total_attempts << "\n";
    std::cout << "Commands captured:   " << total_commands << "\n";

    print_top("Top source IPs", attempts_by_ip);
    print_top("Top usernames", usernames);
    print_top("Top passwords", passwords);
    print_top("Top commands", commands);

    std::cout << "\nTime: " << std::fixed << std::setprecision(1) << ms << " ms\n";
    return 0;
}