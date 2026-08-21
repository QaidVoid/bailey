# bailey shell integration for bash.
#
#     eval "$(bailey hook bash)"
#
# This cannot confine the shell you are in. Landlock restricts a process for its
# lifetime, and this one already exists with the authority it was given. What it
# does is say when a directory has a policy, and start a confined shell when you
# ask for one.

if [[ $- == *i* ]]; then
    __bailey_hook() {
        # PROMPT_COMMAND runs for every prompt; the notice is about arriving
        # somewhere, not about pressing return.
        [[ "$PWD" == "${__bailey_hook_last-}" ]] && return
        __bailey_hook_last="$PWD"

        local line state message reply
        line="$(command bailey hook status --porcelain 2>/dev/null)"
        [[ -n "$line" ]] || return

        state="${line%%$'\t'*}"
        message="${line#*$'\t'}"
        [[ -n "$message" ]] || return

        if [[ "$state" != ready || -z "${__bailey_hook_ask-}" || ! -t 0 ]]; then
            printf '%s\n' "$message" >&2
            return
        fi

        # Asked once per directory: a question re-asked every time you walk past
        # it is answered without being read.
        case " ${__bailey_hook_declined-} " in
            *" $PWD "*) return ;;
        esac

        printf '%s\n' "$message" >&2
        read -r -n 1 -p "bailey: enter a confined shell here? [y/N] " reply </dev/tty
        printf '\n' >&2
        if [[ "$reply" == [yY] ]]; then
            command bailey shell
        else
            __bailey_hook_declined="${__bailey_hook_declined-} $PWD"
        fi
    }

    case "${PROMPT_COMMAND-}" in
        *__bailey_hook*) ;;
        *) PROMPT_COMMAND="__bailey_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
fi
