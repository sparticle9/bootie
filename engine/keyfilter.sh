#!/bin/sh
# Filter stdin to authorized_keys public-key lines, preserving order and
# deduplicating exact lines. Accepts bare keys and options-prefixed entries;
# double-quoted option values may contain whitespace and escaped quotes.
awk '
function is_space(ch) {
    return ch == " " || ch == "\t" || ch == "\r"
}

function skip_spaces(s, pos, n) {
    while (pos <= n && is_space(substr(s, pos, 1)))
        pos++
    return pos
}

function scan_token(s, pos, n,    token, ch, inquote) {
    token = ""
    inquote = 0
    while (pos <= n) {
        ch = substr(s, pos, 1)
        if (!inquote && is_space(ch))
            break
        if (inquote && ch == "\\" && substr(s, pos + 1, 1) == "\"") {
            token = token ch substr(s, pos + 1, 1)
            pos += 2
            continue
        }
        if (ch == "\"")
            inquote = !inquote
        token = token ch
        pos++
    }
    scanned_token = token
    return pos
}

function is_keytype(token) {
    return token ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2|sk-ssh|sk-ecdsa)/
}

function is_base64(token,    alphabet, i, ch) {
    if (token == "")
        return 0
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    for (i = 1; i <= length(token); i++) {
        ch = substr(token, i, 1)
        if (index(alphabet, ch) == 0)
            return 0
    }
    return 1
}

function valid_key_at(s, pos, n,    end, keytype, b64) {
    end = scan_token(s, pos, n)
    keytype = scanned_token
    if (!is_keytype(keytype))
        return 0
    pos = skip_spaces(s, end, n)
    if (pos > n)
        return 0
    scan_token(s, pos, n)
    b64 = scanned_token
    return is_base64(b64)
}

function valid_line(s,    n, pos, end, first) {
    n = length(s)
    pos = skip_spaces(s, 1, n)
    if (pos > n || substr(s, pos, 1) == "#")
        return 0
    end = scan_token(s, pos, n)
    first = scanned_token
    if (is_keytype(first))
        return valid_key_at(s, pos, n)
    pos = skip_spaces(s, end, n)
    if (pos > n)
        return 0
    return valid_key_at(s, pos, n)
}

valid_line($0) && !seen[$0]++
'
