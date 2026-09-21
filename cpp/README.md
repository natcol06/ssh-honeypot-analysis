# C++ log parser

A C++ rewrite of the Python analysis tool, built to compare the two and to
find out where the time actually goes.

The short version: the first C++ attempt was **slower than Python**.
Measuring showed almost all of the time was spent inside the JSON library,
not in reading files or counting. Swapping that one library out made the
final version several times faster than Python.

## Results

Same 117,248 log lines, same report, median of three runs on the same
machine (Windows 11, GCC 16.1, `-O2 -static`):

| Version                 | Time   | Versus Python |
| ----------------------- | ------ | ------------- |
| C++ with nlohmann/json  | 733 ms | 1.6x slower   |
| Python                  | 467 ms | baseline      |
| C++ with simdjson       | 145 ms | 3.2x faster   |

All three print identical counts: 15,128 sessions, 624 hosts connected,
389 that attempted a login, 14,422 login attempts, 14,320 commands.

## Why the first version lost

C++ is not automatically faster than Python. Python's `json` module looks
like Python but is written in C underneath, and it is well tuned.

Timing the C++ version in pieces showed where the work was:

| Step                  | Time   |
| --------------------- | ------ |
| Reading the files     | ~11 ms |
| Parsing the JSON      | ~580 ms |
| Counting and sorting  | the rest |

About 98% of the run was JSON parsing. `nlohmann/json` builds a complete
object in memory for every line, allocating memory for every field,
including the many fields this tool never reads.

`simdjson` takes the opposite approach. Its On Demand API walks the raw
text and pulls out only the fields that are asked for, so fields that go
unused cost almost nothing. That single change accounts for the whole
difference between the two C++ versions; the rest of the code is the same.

## Files

| File             | What it is                                       |
| ---------------- | ------------------------------------------------ |
| `parse.cpp`      | first version, nlohmann/json                     |
| `parse_fast.cpp` | final version, simdjson                          |
| `parse_same.py`  | Python doing exactly the same work, for timing    |

`parse_same.py` exists so the comparison is fair. The main `parse.py` in
the project root does more analysis, so timing against it would have
measured different amounts of work rather than different languages.

## Building

The two JSON libraries are single-file downloads and are not committed
here:

```
curl -L -o json.hpp https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
curl -L -o simdjson.h https://raw.githubusercontent.com/simdjson/simdjson/master/singleheader/simdjson.h
curl -L -o simdjson.cpp https://raw.githubusercontent.com/simdjson/simdjson/master/singleheader/simdjson.cpp
```

Then:

```
g++ -std=c++17 -O2 -static parse.cpp -o parse
g++ -std=c++17 -O2 -static parse_fast.cpp simdjson.cpp -o parse_fast
```

`-O2` turns on optimization, which matters for any timing comparison.
`-static` builds the C++ runtime into the program, which avoids a
library-loading failure seen when running from Git Bash on Windows.

## Running

```
./parse_fast            # reads ../data
./parse_fast some/dir   # reads another folder
python parse_same.py    # the Python version, same output
```

Each prints the counts and the elapsed time. Run each a few times and
compare the middle value, since the first run is usually slower while the
operating system pulls the files into memory.

## Notes and limits

- Timings are from one machine. The ratios matter more than the numbers.
- Both C++ versions parse each line on its own, so one malformed line is
  skipped instead of ending the run. simdjson can go faster still by
  streaming a whole file at once, at the cost of that tolerance.
- The remaining time in the fast version is mostly copying strings into
  hash maps, which is the next thing to attack if it ever needs to be
  faster.