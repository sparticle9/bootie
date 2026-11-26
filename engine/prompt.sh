#!/bin/sh
# Interactive input helper shared by the bootie entrypoint.
#
# bootie_prompt_read sets REPLY. It prefers the controlling terminal because
# in `curl ... | sh` mode stdin is the script itself. BOOTIE_PROMPT_TTY is an
# internal test hook for the tty path; production behavior uses /dev/tty.
bootie_prompt_read() {
    bp_tty=${BOOTIE_PROMPT_TTY:-/dev/tty}
    if { true < "$bp_tty"; } 2>/dev/null; then
        IFS= read -r REPLY < "$bp_tty"
    else
        IFS= read -r REPLY 2>/dev/null || {
            echo "bootie needs a typed answer but has neither a terminal nor piped input." >&2
            echo "run it in an interactive session (ssh -t), or feed answers on stdin." >&2
            return 1
        }
    fi
}

# bootie_prompt_secret reads a line into REPLY with terminal echo disabled
# when attached to a TTY. Falls back to stdin when non-interactive.
bootie_prompt_secret() {
    bp_tty=${BOOTIE_PROMPT_TTY:-/dev/tty}
    if { true < "$bp_tty"; } 2>/dev/null; then
        bp_echo_off=0
        if stty -echo < "$bp_tty" 2>/dev/null; then
            bp_echo_off=1
        fi
        bp_rc=0
        IFS= read -r REPLY < "$bp_tty" || bp_rc=$?
        if [ "$bp_echo_off" = 1 ]; then
            stty echo < "$bp_tty" 2>/dev/null || true
            printf '\n' >&2
        fi
        return "$bp_rc"
    else
        IFS= read -r REPLY 2>/dev/null || {
            echo "bootie needs a password input but has neither a terminal nor piped input." >&2
            echo "run it in an interactive session (ssh -t), or pass --password-file PATH." >&2
            return 1
        }
    fi
}
