# bailey shell integration for fish.
#
#     bailey hook fish | source
#
# This cannot confine the shell you are in. Landlock restricts a process for its
# lifetime, and this one already exists with the authority it was given. What it
# does is say when a directory has a policy, and start a confined shell when you
# ask for one.

if status is-interactive
    function __bailey_hook --on-variable PWD -d "notice a directory's bailey policy"
        set -l line (command bailey hook status --porcelain 2>/dev/null)
        test -n "$line"; or return

        set -l state (string split -f1 -m1 \t -- $line)
        set -l message (string split -f2 -m1 \t -- $line)
        test -n "$message"; or return

        if test "$state" != ready; or not set -q __bailey_hook_ask
            echo $message >&2
            return
        end

        # Asked once per directory: a question re-asked every time you walk past
        # it is answered without being read.
        if contains -- $PWD $__bailey_hook_declined
            return
        end

        echo $message >&2
        read -P "bailey: enter a confined shell here? [y/N] " -l reply
        if test "$reply" = y -o "$reply" = Y
            command bailey shell
        else
            set -g __bailey_hook_declined $__bailey_hook_declined $PWD
        end
    end
end
