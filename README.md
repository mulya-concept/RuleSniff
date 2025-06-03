## RuleSniff
RuleSniff is a pattern-based malware detection engine similar to YARA, which aims to Detect Malware Based on Patterns

![Screenshot 2025-06-03 065533](https://github.com/user-attachments/assets/df6958a8-072e-4341-a0ba-92bf811c8848)

## `RuleSniff` Key Features
| Fitur                           | Deskripsi                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------- |
| 🧠 **Custom Rules (YARA-like)** | Supports YARA-like rule syntax: `strings`, `condition`, `all/any of them`             |
| 📦 **Multi-pattern Match**      | Detects regular strings, hex byte patterns, and obfuscated indicators                 |
| 🧾 **Detailed Scan Report**     | Full output: filename, SHA256, size, scan time, matched rules                   |
| 🧱 **Static Analysis**          | Does not execute files – safe for analyzing malware                              |
| 📜 **ASCII Output Format**      | Professional and easy to read CLI style reports                               |
| 💡 **Match Insight**            | Displays the offset and contents of matched strings in a file.                              |
| 🔒 **Offline Usage**            | Fully usable **without internet connection**                                   |
| 🐍 **No Dependency**            | Only need Python (no need to `pip install` anything)                                  |
| 🚨 **Verdict System**           | Displays conclusion: Clean, Suspicious, or Dangerous (optional for next version) |
