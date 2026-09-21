// parse.cpp - C++ version of parse.py
//
// Reads Cowrie JSON logs and prints the same summary as the Python tool:
// top source IPs, usernames, passwords, and commands, plus totals.
//
// Build:  g++ -std=c++17 -O2 parse.cpp -o parse
// Run:    ./parse            (reads ../data)
//         ./parse some/dir   (reads another folder)

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;
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

// Shorten long values for display. Some attacker commands are nearly
// 12,000 characters, which would wreck the table.
std::string shorten(const std::string& s, size_t max_len = 60) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len - 3) + "...";
}

// Print the n most common entries in a counter, largest first.
// Hash maps have no order, so the entries are copied into a vector and
// sorted. partial_sort only orders the first n, which is cheaper than
// sorting everything when there are thousands of distinct values.
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

int main(int argc, char* argv[]) {
    fs::path folder = (argc > 1) ? argv[1] : "../data";

    auto start = std::chrono::steady_clock::now();

    std::vector<fs::path> files = find_logs(folder);
    if (files.empty()) {
        std::cerr << "No .json logs found in " << folder << "\n";
        return 1;
    }

    Counter attempts_by_ip, usernames, passwords, commands;
    std::unordered_set<std::string> sessions;         // every session id seen
    std::unordered_set<std::string> connected_hosts;  // every IP seen at all

    long total_attempts = 0;
    long total_commands = 0;
    long bad_lines = 0;
    long lines_read = 0;

    for (const auto& path : files) {
        std::ifstream in(path);
        std::string line;

        while (std::getline(in, line)) {
            if (line.empty()) continue;
            lines_read++;

            // parse() normally throws on bad JSON. Passing false makes it
            // return a "discarded" value instead, which is much cheaper
            // than catching an exception on every broken line.
            json event = json::parse(line, nullptr, false);
            if (event.is_discarded()) {
                bad_lines++;
                continue;
            }

            std::string kind = event.value("eventid", "");
            std::string ip = event.value("src_ip", "");
            std::string session = event.value("session", "");

            if (!session.empty()) sessions.insert(session);
            if (!ip.empty()) connected_hosts.insert(ip);

            if (kind == "cowrie.login.success" || kind == "cowrie.login.failed") {
                attempts_by_ip[ip]++;
                usernames[event.value("username", "")]++;
                passwords[event.value("password", "")]++;
                total_attempts++;
            } else if (kind == "cowrie.command.input") {
                commands[event.value("input", "")]++;
                total_commands++;
            }
        }
    }

    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    std::cout << "SSH Honeypot Report (C++)\n";
    std::cout << "=========================\n";
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